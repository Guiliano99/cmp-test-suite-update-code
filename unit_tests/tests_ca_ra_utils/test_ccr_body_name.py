# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1utils import encode_to_der
from resources.ca_ra_utils import (
    _build_ca_cert_response_body,
    enforce_lwcmp_for_ca,
    get_cert_template_from_pkimessage,
    prepare_cert_response,
    verify_popo_for_cert_request,
    verify_sig_pop_for_pki_request,
)
from resources.cmputils import build_ccr_from_key
from resources.keyutils import load_private_key_from_file


class TestCcrBodyName(unittest.TestCase):
    """The CA helpers must accept the cross-certification body `ccr` (RFC 9810 Section 5.1.2, PKIBody [13])."""

    @classmethod
    def setUpClass(cls):
        cls.ccr = build_ccr_from_key(load_private_key_from_file("data/keys/private-key-rsa.pem", password=None))

    def test_ca_cert_response_body_for_ccr(self):
        """
        GIVEN a ccr.
        WHEN a CA certificate response body is built for it without an explicit body name.
        THEN the body is a ccp.
        """
        response = prepare_cert_response(cert_req_id=0, status="rejection", failinfo="badCertTemplate")
        pki_message = _build_ca_cert_response_body(responses=response, request=self.ccr)
        self.assertEqual(pki_message["body"].getName(), "ccp")

    def test_cert_template_from_ccr(self):
        """
        GIVEN a ccr.
        WHEN the certificate template is read from it.
        THEN it is the template of the first CertReqMsg.
        """
        self.assertEqual(
            encode_to_der(get_cert_template_from_pkimessage(self.ccr)),
            encode_to_der(self.ccr["body"]["ccr"][0]["certReq"]["certTemplate"]),
        )

    def test_enforce_lwcmp_accepts_single_ccr(self):
        """
        GIVEN a ccr with one CertReqMsg and certReqId 0.
        WHEN LwCMP is enforced for it.
        THEN no exception is raised.
        """
        enforce_lwcmp_for_ca(self.ccr)

    def test_verify_sig_pop_for_ccr(self):
        """
        GIVEN a ccr with a valid signature POP.
        WHEN the signature POP is verified.
        THEN no exception is raised.
        """
        verify_sig_pop_for_pki_request(self.ccr)

    def test_verify_popo_for_ccr(self):
        """
        GIVEN a ccr with a valid signature POP.
        WHEN the POP of the certificate request is verified.
        THEN no exception is raised.
        """
        verify_popo_for_cert_request(self.ccr)


if __name__ == "__main__":
    unittest.main()
