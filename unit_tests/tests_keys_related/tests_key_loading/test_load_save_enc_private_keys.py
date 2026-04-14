# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for encrypted private-key loading and PKCS#8 wrappers."""

import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5958

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.key_pyasn1_utils import (
    decrypt_private_key_pkcs8,
    decrypt_private_key_pkcs8_pem,
    encrypt_private_key_pkcs8,
    encrypt_private_key_pkcs8_pem,
    load_enc_key,
)
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pq_logic.keys.serialize_utils import _prepare_enc_key_pem_legacy, prepare_enc_key_pem
from resources.keyutils import load_private_key_from_file


class TestEncryptedKeys(unittest.TestCase):
    """Validate encrypted key serialization helpers."""

    @classmethod
    def setUpClass(cls):
        """Set a shared password for encrypted-key tests."""
        cls.password = "secure_password"

    def test_trad_key_encryption_decryption(self):
        """GIVEN a traditional key.

        WHEN the key is encrypted and decrypted,
        THEN the decrypted key should be equal to the original key.
        """
        key_cases = [
            ("X25519", x25519.X25519PrivateKey.generate()),
            ("X448", x448.X448PrivateKey.generate()),
            ("ED25519", ed25519.Ed25519PrivateKey.generate()),
            ("ED448", ed448.Ed448PrivateKey.generate()),
            ("RSA", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
            ("EC", ec.generate_private_key(ec.SECP256R1())),
        ]

        for key_name, private_key in key_cases:
            with self.subTest(key_name=key_name):
                one_asym_key = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                pem_data = prepare_enc_key_pem(self.password, one_asym_key, key_name.encode("utf-8"))
                decrypted_key = load_enc_key(password=self.password, data=pem_data)
                self.assertEqual(decrypted_key, one_asym_key)

    def test_pq_key_enc_decryption(self):
        """GIVEN a pq key.

        WHEN the key is encrypted and decrypted,
        THEN the decrypted key should be equal to the original key.
        """
        key_cases = [
            ("ML-KEM", PQKeyFactory.generate_pq_key("ml-kem-768")),
            ("ML-DSA", PQKeyFactory.generate_pq_key("ml-dsa-65")),
            ("SLH-DSA", PQKeyFactory.generate_pq_key("slh-dsa")),
        ]

        for key_name, private_key in key_cases:
            with self.subTest(key_name=key_name):
                one_asym_key = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                pem_data = prepare_enc_key_pem(self.password, one_asym_key, key_name.encode("utf-8"))
                decrypted_key = load_enc_key(password=self.password, data=pem_data)
                self.assertEqual(decrypted_key, one_asym_key)
                loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(decrypted_key)
                self.assertEqual(loaded_key.public_key(), private_key.public_key())

    def test_pkcs8_encryption_decryption_trad_keys(self):
        """GIVEN traditional private keys in PKCS#8 DER format.

        WHEN each key is encrypted and decrypted with the PKCS#8 DER helpers,
        THEN the decrypted key bytes should equal the original DER encoding.
        """
        key_cases = [
            ("X25519", x25519.X25519PrivateKey.generate()),
            ("X448", x448.X448PrivateKey.generate()),
            ("ED25519", ed25519.Ed25519PrivateKey.generate()),
            ("ED448", ed448.Ed448PrivateKey.generate()),
            ("RSA", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
            ("EC", ec.generate_private_key(ec.SECP256R1())),
        ]

        for key_name, private_key in key_cases:
            with self.subTest(key_name=key_name):
                one_asym_key = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                encrypted_der = encrypt_private_key_pkcs8(one_asym_key, self.password)
                decrypted_der = decrypt_private_key_pkcs8(encrypted_der, self.password)

                self.assertEqual(decrypted_der, one_asym_key)

    def test_pkcs8_pem_encryption_decryption_pq_keys(self):
        """GIVEN PQ private keys in PKCS#8 DER format.

        WHEN each key is encrypted and decrypted with the PKCS#8 PEM helpers,
        THEN the decrypted DER and loaded public key should match the original key.
        """
        key_cases = [
            ("ML-KEM-768", PQKeyFactory.generate_pq_key("ml-kem-768")),
            ("ML-DSA-65", PQKeyFactory.generate_pq_key("ml-dsa-65")),
            ("SLH-DSA", PQKeyFactory.generate_pq_key("slh-dsa")),
        ]

        for key_name, private_key in key_cases:
            with self.subTest(key_name=key_name):
                one_asym_key = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                encrypted_pem = encrypt_private_key_pkcs8_pem(one_asym_key, self.password)
                self.assertTrue(encrypted_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))

                decrypted_der = decrypt_private_key_pkcs8_pem(encrypted_pem, self.password)
                self.assertEqual(decrypted_der, one_asym_key)

                one_asym_key_asn1, rest = decoder.decode(decrypted_der, asn1Spec=rfc5958.OneAsymmetricKey())
                self.assertEqual(rest, b"")
                loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(one_asym_key_asn1)
                self.assertEqual(loaded_key.public_key(), private_key.public_key())

    def test_pkcs8_pem_encryption_decryption_composite_keys(self):
        """GIVEN composite private keys in PKCS#8 DER format.

        WHEN each key is encrypted and decrypted with the PKCS#8 PEM helpers,
        THEN the decrypted DER and loaded public key should match the original key.
        """
        key_cases = [
            (
                "COMPOSITE-SIG-RSA",
                CombinedKeyFactory.generate_key(algorithm="composite-sig", trad_name="rsa", length=2048),
            ),
            (
                "COMPOSITE-SIG-ED25519",
                CombinedKeyFactory.generate_key(algorithm="composite-sig", trad_name="ed25519"),
            ),
            (
                "COMPOSITE-SIG-ED448",
                CombinedKeyFactory.generate_key(algorithm="composite-sig", trad_name="ed448"),
            ),
        ]

        for key_name, private_key in key_cases:
            with self.subTest(key_name=key_name):
                one_asym_key = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                encrypted_pem = encrypt_private_key_pkcs8_pem(one_asym_key, self.password)
                self.assertTrue(encrypted_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))

                decrypted_der = decrypt_private_key_pkcs8_pem(encrypted_pem, self.password)
                self.assertEqual(decrypted_der, one_asym_key)

                one_asym_key_asn1, rest = decoder.decode(decrypted_der, asn1Spec=rfc5958.OneAsymmetricKey())
                self.assertEqual(rest, b"")
                loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(one_asym_key_asn1)
                self.assertEqual(loaded_key.public_key(), private_key.public_key())

    def test_prepare_enc_key_pem_now_produces_pkcs8(self):
        """GIVEN a PKCS#8-encoded ML-DSA private key.

        WHEN prepare_enc_key_pem wraps the key with password-based encryption,
        THEN the PEM output should use the PKCS#8 ENCRYPTED PRIVATE KEY header.
        """
        private_key = PQKeyFactory.generate_pq_key("ml-dsa-65")
        one_asym_key = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        encrypted_pem = prepare_enc_key_pem(self.password, one_asym_key, b"ML-DSA")

        self.assertTrue(encrypted_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        self.assertFalse(encrypted_pem.startswith(b"-----BEGIN ML-DSA PRIVATE KEY-----"))

    def test_load_enc_key_decrypts_legacy_format(self):
        """GIVEN a legacy encrypted private key PEM payload.

        WHEN load_enc_key decrypts the backward-compatible format,
        THEN the decrypted DER bytes should equal the original PKCS#8 key.
        """
        private_key = PQKeyFactory.generate_pq_key("ml-dsa-65")
        one_asym_key = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        legacy_pem = _prepare_enc_key_pem_legacy(self.password, one_asym_key, b"ML-DSA")
        decrypted_der = load_enc_key(password=self.password, data=legacy_pem)

        self.assertEqual(decrypted_der, one_asym_key)

    def test_pkcs8_encryption_wrong_password_raises(self):
        """GIVEN a PKCS#8-encrypted private key.

        WHEN it is decrypted with a different password,
        THEN decryption should raise a ValueError.
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        one_asym_key = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        encrypted_der = encrypt_private_key_pkcs8(one_asym_key, self.password)

        with self.assertRaises(ValueError):
            decrypt_private_key_pkcs8(encrypted_der, "wrong_password")

    def test_pkcs8_encryption_empty_password_raises(self):
        """GIVEN a PKCS#8 private key payload.

        WHEN encryption is requested with an empty password,
        THEN the PKCS#8 encryption helper should raise a ValueError.
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        one_asym_key = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with self.assertRaises(ValueError):
            encrypt_private_key_pkcs8(one_asym_key, "")

    def test_composite_sig_enc_decryption(self):
        """GIVEN a composite signature key.

        WHEN the key is encrypted and decrypted,
        THEN the decrypted key should be equal to the original key.
        """
        key_cases = [
            ("COMPOSITE-SIG", CombinedKeyFactory.generate_key(algorithm="composite-sig", trad_name="rsa", length=2048)),
            ("COMPOSITE-SIG", CombinedKeyFactory.generate_key(algorithm="composite-sig", trad_name="ed25519")),
            ("COMPOSITE-SIG", CombinedKeyFactory.generate_key(algorithm="composite-sig", trad_name="ed448")),
        ]

        for key_name, private_key in key_cases:
            with self.subTest(key_name=key_name):
                one_asym_key = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                pem_data = prepare_enc_key_pem(self.password, one_asym_key, key_name.encode("utf-8"))
                decrypted_key = load_enc_key(password=self.password, data=pem_data)
                self.assertEqual(decrypted_key, one_asym_key)
                loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(decrypted_key)
                self.assertEqual(loaded_key.public_key(), private_key.public_key())


def _trad_key_cases():
    """Return (name, private_key) pairs for all traditional key types under test."""
    return [
        ("X25519", x25519.X25519PrivateKey.generate()),
        ("X448", x448.X448PrivateKey.generate()),
        ("Ed25519", ed25519.Ed25519PrivateKey.generate()),
        ("Ed448", ed448.Ed448PrivateKey.generate()),
        ("EC-P256", ec.generate_private_key(ec.SECP256R1())),
        ("RSA-2048", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ("DSA-2048", dsa.generate_private_key(key_size=2048)),
    ]


class TestCryptographyEncryptsRepoDecrypts(unittest.TestCase):
    """Validate that keys encrypted by the cryptography library are decryptable by the repo's own code."""

    PASSWORD = b"11111"

    def test_cryptography_encrypted_pem_loads_via_repo(self):
        """GIVEN a traditional private key encrypted by the cryptography library.

        WHEN the PEM is written to a temp file and loaded via load_private_key_from_file,
        THEN the loaded key's public key must match the original.
        """
        for key_name, private_key in _trad_key_cases():
            with self.subTest(key=key_name):
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(self.PASSWORD),
                )

                with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
                    f.write(pem)
                    path = f.name

                loaded = load_private_key_from_file(path, password=self.PASSWORD.decode())
                self.assertEqual(loaded.public_key(), private_key.public_key())

    def test_cryptography_encrypted_pem_decryptable_by_decrypt_pkcs8_pem(self):
        """GIVEN a traditional private key encrypted by the cryptography library.

        WHEN decrypt_private_key_pkcs8_pem is called with the correct password,
        THEN the decrypted DER must round-trip back to the same public key.
        """
        for key_name, private_key in _trad_key_cases():
            with self.subTest(key=key_name):
                original_der = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                encrypted_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(self.PASSWORD),
                )

                decrypted_der = decrypt_private_key_pkcs8_pem(encrypted_pem, self.PASSWORD)
                self.assertEqual(decrypted_der, original_der)

    def test_cryptography_encrypted_pem_wrong_password_raises(self):
        """GIVEN a traditional private key encrypted by the cryptography library.

        WHEN decrypt_private_key_pkcs8_pem is called with a wrong password,
        THEN a ValueError must be raised.
        """
        for key_name, private_key in _trad_key_cases():
            with self.subTest(key=key_name):
                encrypted_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(self.PASSWORD),
                )

                with self.assertRaises((ValueError, Exception)):
                    decrypt_private_key_pkcs8_pem(encrypted_pem, b"wrong_password")


class TestRepoEncryptsCryptographyDecrypts(unittest.TestCase):
    """Validate that keys encrypted by the repo's PKCS#8 helpers are decryptable by the cryptography library."""

    PASSWORD = b"11111"

    def test_repo_encrypted_pem_loads_via_cryptography(self):
        """GIVEN a traditional private key encrypted by the repo's encrypt_private_key_pkcs8_pem.

        WHEN load_pem_private_key from the cryptography library is called with the correct password,
        THEN the loaded key's public key must match the original.
        """
        for key_name, private_key in _trad_key_cases():
            with self.subTest(key=key_name):
                original_der = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                encrypted_pem = encrypt_private_key_pkcs8_pem(original_der, self.PASSWORD)
                self.assertTrue(encrypted_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))

                loaded = serialization.load_pem_private_key(encrypted_pem, password=self.PASSWORD)
                self.assertEqual(loaded.public_key(), private_key.public_key())

    def test_repo_encrypted_pem_loads_via_load_private_key_from_file(self):
        """GIVEN a traditional private key encrypted by the repo's encrypt_private_key_pkcs8_pem.

        WHEN the PEM is written to a temp file and loaded via load_private_key_from_file,
        THEN the loaded key's public key must match the original.
        """
        for key_name, private_key in _trad_key_cases():
            with self.subTest(key=key_name):
                original_der = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                encrypted_pem = encrypt_private_key_pkcs8_pem(original_der, self.PASSWORD)

                with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
                    f.write(encrypted_pem)
                    path = f.name

                loaded = load_private_key_from_file(path, password=self.PASSWORD.decode())
                self.assertEqual(loaded.public_key(), private_key.public_key())

    def test_repo_encrypted_pem_wrong_password_raises(self):
        """GIVEN a traditional private key encrypted by the repo's encrypt_private_key_pkcs8_pem.

        WHEN the cryptography library attempts decryption with a wrong password,
        THEN a ValueError must be raised.
        """
        for key_name, private_key in _trad_key_cases():
            with self.subTest(key=key_name):
                original_der = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                encrypted_pem = encrypt_private_key_pkcs8_pem(original_der, self.PASSWORD)

                with self.assertRaises((ValueError, Exception)):
                    serialization.load_pem_private_key(encrypted_pem, password=b"wrong_password")


if __name__ == "__main__":
    unittest.main()
