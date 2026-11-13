# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch

from mock_ca.ca_handler import CAHandler
from mock_ca.mock_fun import CertStateEnum
from resources.certbuildutils import build_certificate
from resources.certutils import cert_in_list

from resources.cmputils import (
    build_cmp_revoke_request,
    build_ir_from_key,
    get_cert_from_pkimessage,
    get_pkistatusinfo,
    parse_pkimessage,
)
from resources.exceptions import CertRevoked
from resources.keyutils import generate_key
from resources.protectionutils import protect_pkimessage
from unit_tests.utils_for_test import load_ca_cert_and_key, try_encode_pyasn1


class TestMockCaRevokedRevive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.ca_handler = CAHandler(ca_cert=cls.ca_cert, ca_key=cls.ca_key)

    def test_hybrid_issuing_rejects_revoked_certificate(self):
        """
        GIVEN a composite signature certificate issued by the CA and revoked, in the first extraCerts entry.
        WHEN the hybrid handler checks the request before issuing, as a composite signature, a related
        certificate and a cert discovery certificate.
        THEN each check raises `CertRevoked`.
        """
        key = generate_key("composite-sig")
        cert, _ = build_certificate(
            private_key=key, common_name="CN=Hans the Tester", ca_key=self.ca_key, ca_cert=self.ca_cert
        )
        self.ca_handler.state.certificate_db.add_cert(cert=cert, cert_state=CertStateEnum.CONFIRMED)
        self.ca_handler.rev_handler.mark_as_revoked(cert, reason="keyCompromise")
        request = build_ir_from_key(key, common_name="CN=Hans the Tester", sender="CN=Hans the Tester", for_mac=True)
        request["extraCerts"].append(cert)

        with self.subTest(hybrid_type="composite-sig"):
            with self.assertRaises(CertRevoked):
                self.ca_handler.hybrid_handler.is_revoked_for_issuing(request=request)

        for hybrid_type in ["related-cert", "cert-discovery"]:
            with self.subTest(hybrid_type=hybrid_type):
                with patch("mock_ca.hybrid_handler.is_hybrid_cert", return_value=hybrid_type):
                    with self.assertRaises(CertRevoked):
                        self.ca_handler.hybrid_handler.is_revoked_for_issuing(request=request)

    def test_revocation_and_revive(self):
        """
        GIVEN a certificate.
        WHEN a revocation request is processed and the certificate is revoked and a revive request is processed,
        THEN is the certificate successfully revived.
        """
        key = generate_key("ecc")
        ir = build_ir_from_key(
            key, common_name="CN=Hans the Tester", sender="CN=Hans the Tester", implicit_confirm=True, for_mac=True
        )
        prot_ir = protect_pkimessage(ir, "pbmac1", password="SiemensIT")

        der_data = try_encode_pyasn1(prot_ir)
        request = parse_pkimessage(der_data)

        response = self.ca_handler.process_normal_request(request)
        status = get_pkistatusinfo(response)
        self.assertEqual(response["body"].getName(), "ip", response["body"].prettyPrint())
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())

        cert = get_cert_from_pkimessage(response)

        der_data = try_encode_pyasn1(cert)
        self.assertTrue(cert_in_list(cert, self.ca_handler.get_details("issued_certs")), "Expected cert in issued_certs")

        # Revocation
        rr = build_cmp_revoke_request(cert=cert, reason="keyCompromise")
        prot_rr = protect_pkimessage(rr, "signature", private_key=key, cert=cert, certs_dir="data/unittest/")

        response = self.ca_handler.process_normal_request(prot_rr)
        self.assertEqual(response["body"].getName(), "rp", response["body"].prettyPrint())
        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())

        # Revive
        revive_request = build_cmp_revoke_request(cert=cert, reason="removeFromCRL")
        prot_revive_request = protect_pkimessage(
            revive_request, "signature", private_key=key, cert=cert, certs_dir="data/unittest/"
        )
        response = self.ca_handler.process_normal_request(prot_revive_request)
        self.assertEqual(response["body"].getName(), "rp", response["body"].prettyPrint())
        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())
        self.assertTrue("revive" in str(status["statusString"][0]).lower())

        # Check if the certificate is not revoked,
        # by issuing a certificate request with the revived certificate and key.
        key2 = generate_key("ecc")
        ir2 = build_ir_from_key(
            key2,
            common_name="CN=Hans the Tester",
            recipient="Mock-CA",
            exclude_fields="sender,senderKID",
            implicit_confirm=True,
        )
        prot_ir2 = protect_pkimessage(ir2, "signature", private_key=key, cert=cert, certs_dir="data/unittest/")
        response = self.ca_handler.process_normal_request(prot_ir2)
        self.assertEqual(response["body"].getName(), "ip", response["body"].prettyPrint())
        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())
