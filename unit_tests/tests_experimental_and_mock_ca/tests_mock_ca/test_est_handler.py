# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the EST server handler (RFC 7030).

These tests exercise ``mock_ca.est_handler.EstHandler`` directly with a
lightweight RSA CA, so they run quickly and do not require post-quantum
dependencies or a live server.
"""

import unittest

from cryptography.hazmat.primitives.serialization import load_der_private_key

from mock_ca.est_handler import EstHandler
from resources import est_utils
from resources.certbuildutils import build_certificate
from resources.keyutils import generate_key


class _CollectingState:
    """Minimal stand-in for ``MockCAState`` that records added certificates."""

    def __init__(self):
        self.added = []

    def add_certs(self, certs, was_confirmed=False):  # noqa: ARG002 - signature parity
        self.added.extend(certs)


class TestEstHandler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = generate_key("rsa", length=2048)
        cls.ca_cert, _ = build_certificate(
            private_key=cls.ca_key, common_name="CN=EST Unit Test CA", is_ca=True
        )

    def _handler(self, **kwargs) -> EstHandler:
        return EstHandler(ca_cert=self.ca_cert, ca_key=self.ca_key, **kwargs)

    def test_cacerts_returns_ca_chain(self):
        """
        GIVEN an EST handler.
        WHEN /cacerts is requested.
        THEN a base64 certs-only bundle with the CA certificate is returned.
        """
        handler = self._handler()
        certs = est_utils.parse_est_cacerts_response(handler.get_cacerts())
        self.assertEqual(len(certs), 1)

    def test_simpleenroll_issues_certificate(self):
        """
        GIVEN a PKCS#10 request.
        WHEN /simpleenroll is processed.
        THEN a certificate is issued and tracked in the state.
        """
        state = _CollectingState()
        handler = self._handler(state=state)
        csr = est_utils.build_est_csr(generate_key("ec"), "CN=device.example.com")
        body = est_utils.build_est_enroll_request_body(csr)

        resp = handler.handle_enroll(body)
        certs = est_utils.parse_est_enroll_response(resp)
        self.assertEqual(len(certs), 1)
        self.assertEqual(len(handler.issued_certs), 1)
        self.assertEqual(len(state.added), 1)
        # The issued cert must be parseable as a real certificate.
        cert = est_utils.parse_est_certificate(certs[0])
        self.assertTrue(cert["tbsCertificate"]["subject"].isValue)

    def test_simplereenroll_issues_certificate(self):
        """
        GIVEN a PKCS#10 request.
        WHEN /simplereenroll is processed.
        THEN a certificate is issued.
        """
        handler = self._handler()
        csr = est_utils.build_est_csr(generate_key("ec"), "CN=reenroll.example.com")
        body = est_utils.build_est_enroll_request_body(csr)
        certs = est_utils.parse_est_enroll_response(handler.handle_enroll(body, reenroll=True))
        self.assertEqual(len(certs), 1)

    def test_csrattrs_empty_by_default(self):
        """
        GIVEN a handler without advertised CSR attributes.
        WHEN /csrattrs is requested.
        THEN the response body is empty (HTTP 204 at the transport layer).
        """
        handler = self._handler()
        self.assertEqual(handler.get_csrattrs(), b"")

    def test_csrattrs_advertises_configured_oids(self):
        """
        GIVEN a handler configured with CSR attribute OIDs.
        WHEN /csrattrs is requested.
        THEN those OIDs are returned in the CsrAttrs structure.
        """
        oids = ["1.2.840.113549.1.9.7", "1.3.6.1.5.5.7.1.1"]
        handler = self._handler(csr_attr_oids=oids)
        parsed = est_utils.parse_est_csrattrs_response(handler.get_csrattrs())
        self.assertEqual(parsed, oids)

    def test_serverkeygen_generates_key_and_certificate(self):
        """
        GIVEN a PKCS#10 request.
        WHEN /serverkeygen is processed.
        THEN a multipart/mixed response with a usable private key and an issued
             certificate is returned.
        """
        handler = self._handler()
        csr = est_utils.build_est_csr(generate_key("ec"), "CN=serverkeygen.example.com")
        body = est_utils.build_est_enroll_request_body(csr)

        content_type, multipart = handler.handle_serverkeygen(body)
        self.assertIn("multipart/mixed", content_type)
        key_der, certs = est_utils.parse_est_serverkeygen_response(content_type, multipart)
        # The returned private key must load as a valid PKCS#8 key.
        load_der_private_key(key_der, password=None)
        self.assertEqual(len(certs), 1)


if __name__ == "__main__":
    unittest.main()
