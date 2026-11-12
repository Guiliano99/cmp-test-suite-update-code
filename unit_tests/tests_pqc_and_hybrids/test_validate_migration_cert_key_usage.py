# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_certificate
from resources.certutils import validate_migration_certificate_key_usage
from resources.keyutils import generate_key


class TestValidateMigrationCertificateKeyUsage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_key = generate_key("ed25519")

    def test_ml_dsa_digital_signature(self):
        """
        GIVEN an ML-DSA-44 certificate with the keyUsage `digitalSignature`.
        WHEN validate_migration_certificate_key_usage is called,
        THEN no exception is raised.
        """
        cert, _ = build_certificate(private_key=generate_key("ml-dsa-44"), key_usage="digitalSignature")
        validate_migration_certificate_key_usage(cert)

    def test_ml_kem_key_encipherment(self):
        """
        GIVEN an ML-KEM-768 certificate with the keyUsage `keyEncipherment`.
        WHEN validate_migration_certificate_key_usage is called,
        THEN no exception is raised.
        """
        cert, _ = build_certificate(
            private_key=generate_key("ml-kem-768"), key_usage="keyEncipherment", ca_key=self.ca_key
        )
        validate_migration_certificate_key_usage(cert)

    def test_traditional_key_is_unsupported(self):
        """
        GIVEN an Ed25519 certificate with the keyUsage `digitalSignature`.
        WHEN validate_migration_certificate_key_usage is called,
        THEN a ValueError is raised, because the key is neither a PQ signature key nor a KEM key.
        """
        cert, _ = build_certificate(private_key=self.ca_key, key_usage="digitalSignature")
        with self.assertRaisesRegex(ValueError, "Unsupported public key type"):
            validate_migration_certificate_key_usage(cert)


if __name__ == "__main__":
    unittest.main()
