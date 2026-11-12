# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_certificate, prepare_cert_template, prepare_extensions
from resources.certutils import is_ca_cert, validate_ca_cross_signed_cert
from resources.keyutils import generate_key
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestIsCaCert(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = generate_key("ed25519")

    def test_ca_false_is_not_a_ca(self):
        """
        GIVEN a certificate whose BasicConstraints extension has `cA` FALSE (the DEFAULT, omitted in DER).
        WHEN is_ca_cert is called,
        THEN False is returned.
        """
        cert, _ = build_certificate(private_key=self.key, extensions=prepare_extensions(is_ca=False))
        self.assertIs(is_ca_cert(cert), False)

    def test_ca_true_is_a_ca(self):
        """
        GIVEN a certificate whose BasicConstraints extension has `cA` TRUE.
        WHEN is_ca_cert is called,
        THEN True is returned.
        """
        cert, _ = build_certificate(private_key=self.key, extensions=prepare_extensions(is_ca=True))
        self.assertIs(is_ca_cert(cert), True)

    def test_cross_signed_cert_must_be_ca(self):
        """
        GIVEN an end-entity certificate with `cA` FALSE, signed by the test Root CA.
        WHEN validate_ca_cross_signed_cert is called with it as the cross-signed certificate,
        THEN a ValueError is raised, because the certificate is not a CA certificate.
        """
        ca_cert, ca_key = load_ca_cert_and_key()
        ee_cert, _ = build_certificate(
            private_key=self.key,
            common_name="CN=Not A CA",
            ca_key=ca_key,
            ca_cert=ca_cert,
            extensions=prepare_extensions(is_ca=False, key=self.key, ca_key=ca_key.public_key()),
        )
        template = prepare_cert_template(self.key, subject="CN=Not A CA")
        with self.assertRaisesRegex(ValueError, "not a CA certificate"):
            validate_ca_cross_signed_cert(ee_cert, template, ca_cert)


if __name__ == "__main__":
    unittest.main()
