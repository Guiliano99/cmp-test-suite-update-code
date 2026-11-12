# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest import mock

from pq_logic.hybrid_issuing import prepare_catalyst_cert_req_msg_approach
from pq_logic.hybrid_sig.catalyst_logic import load_catalyst_public_key
from resources import protectionutils
from resources.ca_ra_utils import get_public_key_from_cert_req_msg
from resources.keyutils import load_private_key_from_file, generate_key


class TestPrepareCatalystCertReq(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ec_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.pq_kem = load_private_key_from_file("data/keys/private-key-ml-kem-768-seed.pem")
        cls.pq_mldsa = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.common_name = "CN=Hans the Tester"

    def test_trad_sig_key_and_pq_sig_key(self):
        """
        GIVEN a traditional signature key and a post-quantum signature key.
        WHEN preparing a certificate request message,
        THEN should the structure be correctly populated.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.ec_key,
            alt_key=self.pq_mldsa,
            subject=self.common_name,
        )

        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        self.assertEqual(public_key, self.ec_key.public_key())
        loaded_key = load_catalyst_public_key(cert_req_msg["certReq"]["certTemplate"]["extensions"])
        self.assertEqual(loaded_key, self.pq_mldsa.public_key())

    def test_pq_sig_and_trad_sig_key(self):
        """
        GIVEN a post-quantum signature key and a traditional signature key.
        WHEN preparing a certificate request message,
        THEN should the structure be correctly populated.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.pq_mldsa,
            alt_key=self.ec_key,
            subject=self.common_name,
        )

        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        self.assertEqual(public_key, self.pq_mldsa.public_key())
        loaded_key = load_catalyst_public_key(cert_req_msg["certReq"]["certTemplate"]["extensions"])
        self.assertEqual(loaded_key, self.ec_key.public_key())

    def test_pq_kem_and_trad_sig_key(self):
        """
        GIVEN a post-quantum key encapsulation key and a traditional signature key.
        WHEN preparing a certificate request message,
        THEN should the structure be correctly populated.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.pq_kem,
            alt_key=self.ec_key,
            subject=self.common_name,
        )
        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        self.assertEqual(public_key, self.pq_kem.public_key())
        loaded_key = load_catalyst_public_key(cert_req_msg["certReq"]["certTemplate"]["extensions"])
        self.assertEqual(loaded_key, self.ec_key.public_key())

    def test_trad_sig_key_and_pq_kem(self):
        """
        GIVEN a traditional signature key and a post-quantum KEM key.
        WHEN preparing a certificate request message,
        THEN should the structure be correctly populated.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.ec_key,
            alt_key=self.pq_kem,
            subject=self.common_name,
        )
        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        self.assertEqual(public_key, self.ec_key.public_key())
        loaded_key = load_catalyst_public_key(cert_req_msg["certReq"]["certTemplate"]["extensions"])
        self.assertEqual(loaded_key, self.pq_kem.public_key())


    def test_split_composite_key(self):
        """
        GIVEN a composite key.
        WHEN preparing a certificate request message,
        THEN should the structure be correctly populated.
        """
        key = generate_key("composite-sig")
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=key.pq_key,
            alt_key=key.trad_key,
            subject=self.common_name,
        )
        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        self.assertEqual(public_key, key.pq_key.public_key())
        loaded_key = load_catalyst_public_key(cert_req_msg["certReq"]["certTemplate"]["extensions"])
        self.assertEqual(loaded_key, key.trad_key.public_key())

    def test_bad_pop_with_two_signature_keys_changes_signature(self):
        """
        GIVEN a traditional and a post-quantum signature key, and a signer whose output starts with 0x01.
        WHEN a Catalyst `CertReqMsg` is prepared with `bad_pop=True`,
        THEN the POP signature differs from the computed signature.
        """
        real_sign = protectionutils.sign_data_with_alg_id
        signed = []

        def _sign_first_byte_01(*args, **kwargs):
            signed.append(b"\x01" + real_sign(*args, **kwargs)[1:])
            return signed[-1]

        with mock.patch.object(protectionutils, "sign_data_with_alg_id", side_effect=_sign_first_byte_01):
            cert_req_msg = prepare_catalyst_cert_req_msg_approach(
                first_key=self.ec_key, alt_key=self.pq_mldsa, bad_pop=True
            )

        # The alternative POP is signed first, so the last signature is the first-key POP.
        self.assertEqual(len(signed), 2)
        popo_signature = cert_req_msg["popo"]["signature"]["signature"].asOctets()
        self.assertNotEqual(popo_signature, signed[-1])
