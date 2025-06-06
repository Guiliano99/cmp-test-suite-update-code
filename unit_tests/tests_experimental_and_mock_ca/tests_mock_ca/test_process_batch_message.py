# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from mock_ca.ca_handler import CAHandler
from pyasn1_alt_modules import rfc9481

from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import is_bit_set
from resources.certutils import parse_certificate
from resources.cmputils import build_ir_from_key, build_nested_pkimessage, generate_unique_byte_values, \
    get_cmp_message_type, get_pkistatusinfo
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file


class TestProcessBatchMessage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.trusted_dir = "data/unittest"
        cls.ra_key = cls.key
        cls.ra_cert = parse_certificate(load_and_decode_pem_file("data/trusted_ras/ra_cms_cert_ecdsa.pem"))
        cls.cm = "CN=Hans the Tester"
        cls.password = b"SiemensIT"
        cls.ca_handler = CAHandler(
            trusted_ras_dir="data/trusted_ras",
            pre_shared_secret=cls.password,
        )

    def _generate_nested_message(
        self,
        bad_message_check: bool = False,
        include_recip_nonce: bool = False,
    ) -> PKIMessageTMP:
        """Generate a nested message from a list of messages.

        :param bad_message_check: Whether to generate a bad protection.
        :param include_recip_nonce: Whether to include the recipient nonce.
        :return: The populated nested message.
        """
        unique_vals = generate_unique_byte_values(length=9, size=16)
        trans_id = unique_vals[:3]
        sender_nonce = unique_vals[3:6]
        recip_nonce = unique_vals[6:]

        ir2 = build_ir_from_key(
            self.key,
            cm=self.cm,
            sender=self.cm,
            transaction_id=trans_id[0],
            sender_nonce=sender_nonce[0],
            recip_nonce=recip_nonce[0] if include_recip_nonce else None,
            for_mac=True,
        )

        ir = build_ir_from_key(
            self.key,
            cm=self.cm + "1",
            sender=self.cm + "1",
            transaction_id=trans_id[1],
            sender_nonce=sender_nonce[1],
            recip_nonce=recip_nonce[1] if include_recip_nonce else None,
            for_mac=True,
        )

        ir = protect_pkimessage(
            pki_message=ir,
            protection="pbmac1",
            password=self.password,
        )

        ir2 = protect_pkimessage(
            pki_message=ir2, protection="pbmac1", password=self.password, bad_message_check=bad_message_check
        )

        nested = build_nested_pkimessage(
            other_messages=[ir, ir2],
            transaction_id=trans_id[2],
            sender_nonce=sender_nonce[2],
            recip_nonce=recip_nonce[2] if include_recip_nonce else None,
        )
        return protect_pkimessage(
            pki_message=nested,
            protection="signature",
            cert=self.ra_cert,
            private_key=self.ra_key,
        )

    def test_process_batch_message(self):
        """Test processing a batch message."""
        nested = self._generate_nested_message(False, False)
        self.assertEqual(nested["body"].getName(), "nested")
        self.assertEqual(len(nested["body"]["nested"]), 2)
        self.assertEqual(nested["body"]["nested"][0]["body"].getName(), "ir")

        response = self.ca_handler.process_normal_request(nested)
        self.assertEqual(response["body"].getName(), "nested")
        self.assertEqual(len(response["body"]["nested"]), 2)
        self.assertEqual(response["body"]["nested"][0]["body"].getName(), "ip")
        self.assertEqual(response["body"]["nested"][1]["body"].getName(), "ip")

        self.assertEqual(response["body"]["nested"][0]["header"]["protectionAlg"]["algorithm"], rfc9481.id_PBMAC1)
        self.assertEqual(response["body"]["nested"][1]["header"]["protectionAlg"]["algorithm"], rfc9481.id_PBMAC1)

    def test_process_batch_message_bad_message_check(self):
        """Test processing a batch message with bad message check."""
        nested = self._generate_nested_message(True, False)
        response = self.ca_handler.process_normal_request(nested)
        self.assertEqual(get_cmp_message_type(response), "error")
        pki_status_info = get_pkistatusinfo(response)
        result = is_bit_set(pki_status_info["failInfo"], "badMessageCheck")
        self.assertTrue(result)

        texts = [x.prettyPrint() for x in pki_status_info["statusString"]]

        self.assertIn("Invalid inner batch PKIMessage protection at index 1.", texts)
