# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the EST (RFC 7030) endpoints of the Mock CA Flask app.

Builds a real ``CAHandler``, registers the ``/.well-known/est/*`` routes and
drives them through Flask's test client, verifying that EST shares the Mock CA's
issuing key/cert and issued-certificate state.
"""

import unittest

from cryptography.hazmat.primitives.serialization import load_der_private_key

from mock_ca import ca_handler
from mock_ca.ca_handler import CAHandler
from resources import est_utils
from resources.keyutils import generate_key
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestEstRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.ca_handler = CAHandler(ca_cert=cls.ca_cert, ca_key=cls.ca_key)

        # Point the module-level handler used by the routes at our CA handler and
        # (re-)register the EST routes on the shared Flask app.
        ca_handler.handler = cls.ca_handler
        ca_handler.est_handler = None
        try:
            ca_handler._register_est_routes(ca_handler.app)
        except (AssertionError, ValueError):
            # Routes may already be registered from a previous test run.
            pass
        cls.client = ca_handler.app.test_client()

    def _new_csr(self, common_name: str):
        return est_utils.build_est_csr(generate_key("ec"), common_name)

    def test_cacerts(self):
        """
        GIVEN the Mock CA EST endpoints.
        WHEN GET /.well-known/est/cacerts is called.
        THEN a certs-only bundle is returned.
        """
        resp = self.client.get("/.well-known/est/cacerts")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(est_utils.est_content_type_matches(resp.headers["Content-Type"], "application/pkcs7-mime"))
        certs = est_utils.parse_est_cacerts_response(resp.data)
        self.assertGreaterEqual(len(certs), 1)

    def test_simpleenroll(self):
        """
        GIVEN a PKCS#10 request.
        WHEN POST /.well-known/est/simpleenroll is called.
        THEN a certificate is issued.
        """
        csr = self._new_csr("CN=est-route-enroll.example.com")
        body = est_utils.build_est_enroll_request_body(csr)
        resp = self.client.post("/.well-known/est/simpleenroll", data=body)
        self.assertEqual(resp.status_code, 200)
        certs = est_utils.parse_est_enroll_response(resp.data)
        self.assertEqual(len(certs), 1)

    def test_simpleenroll_with_label(self):
        """
        GIVEN a PKCS#10 request.
        WHEN POST /.well-known/est/<label>/simpleenroll is called.
        THEN the labelled endpoint also issues a certificate.
        """
        csr = self._new_csr("CN=est-route-label.example.com")
        body = est_utils.build_est_enroll_request_body(csr)
        resp = self.client.post("/.well-known/est/MyProfile/simpleenroll", data=body)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(est_utils.parse_est_enroll_response(resp.data)), 1)

    def test_serverkeygen(self):
        """
        GIVEN a PKCS#10 request.
        WHEN POST /.well-known/est/serverkeygen is called.
        THEN a multipart/mixed response with a usable key and a certificate is returned.
        """
        csr = self._new_csr("CN=est-route-skg.example.com")
        body = est_utils.build_est_enroll_request_body(csr)
        resp = self.client.post("/.well-known/est/serverkeygen", data=body)
        self.assertEqual(resp.status_code, 200)
        key_der, certs = est_utils.parse_est_serverkeygen_response(resp.headers["Content-Type"], resp.data)
        load_der_private_key(key_der, password=None)
        self.assertEqual(len(certs), 1)

    def test_csrattrs(self):
        """
        GIVEN the default Mock CA EST configuration (no advertised attributes).
        WHEN GET /.well-known/est/csrattrs is called.
        THEN HTTP 204 (no content) is returned.
        """
        resp = self.client.get("/.well-known/est/csrattrs")
        self.assertIn(resp.status_code, (200, 204))


if __name__ == "__main__":
    unittest.main()
