# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from keyutils_py.types import DHPrivateKey, DHPublicKey, DSAPrivateKey, DSAPublicKey, PrivateKey, PublicKey, SignKey, VerifyKey

from resources.convertutils import ensure_is_sign_key, subject_public_key_info_from_pubkey
from resources.cryptoutils import sign_data, verify_signature
from resources.keyutils import generate_key, get_key_name, load_private_key_from_file, load_public_key_from_spki, save_key
from resources.oid_mapping import get_alg_oid_from_key_hash
from pyasn1_alt_modules.rfc5480 import id_dsa_with_sha256


class TestDSAandDHKeys(unittest.TestCase):
    """DSA and DH keys are the `keyutils_py` key classes, wherever the suite creates or loads them."""

    @classmethod
    def setUpClass(cls):
        cls.dsa_key = generate_key("dsa")
        cls.dh_key = generate_key("dh", length=512)

    def test_generate_key_returns_keyutils_keys(self):
        """
        GIVEN the algorithms `dsa` and `dh`.
        WHEN a key is generated.
        THEN the keys are the `keyutils_py` classes and are valid private and signing key types.
        """
        self.assertIsInstance(self.dsa_key, DSAPrivateKey)
        self.assertIsInstance(self.dh_key, DHPrivateKey)
        self.assertIsInstance(self.dsa_key.public_key(), DSAPublicKey)
        self.assertIsInstance(self.dh_key.public_key(), DHPublicKey)
        self.assertIsInstance(self.dsa_key, PrivateKey)
        self.assertIsInstance(self.dh_key, PrivateKey)
        self.assertIsInstance(self.dsa_key, SignKey)
        self.assertIsInstance(self.dsa_key.public_key(), PublicKey)
        self.assertIsInstance(self.dsa_key.public_key(), VerifyKey)

    def test_dsa_key_is_a_sign_key(self):
        """
        GIVEN a generated DSA key.
        WHEN it is checked to be allowed to sign.
        THEN the key is accepted.
        """
        self.assertIs(ensure_is_sign_key(self.dsa_key), self.dsa_key)

    def test_dsa_sign_and_verify(self):
        """
        GIVEN a DSA key.
        WHEN data is signed with SHA-256 and verified.
        THEN the signature is valid, and not for other data.
        """
        signature = sign_data(b"data", self.dsa_key, hash_alg="sha256")
        verify_signature(self.dsa_key.public_key(), signature, b"data", hash_alg="sha256")
        with self.assertRaises(InvalidSignature):
            verify_signature(self.dsa_key.public_key(), signature, b"other data", hash_alg="sha256")

    def test_dsa_signature_oid(self):
        """
        GIVEN a DSA key.
        WHEN the signature algorithm OID is looked up for SHA-256.
        THEN it is `id-dsa-with-sha256`.
        """
        self.assertEqual(get_alg_oid_from_key_hash(self.dsa_key, "sha256"), id_dsa_with_sha256)

    def test_key_names(self):
        """
        GIVEN a DSA and a DH key.
        WHEN the key name is requested.
        THEN `dsa` and `dh` are returned, for the private and the public key.
        """
        self.assertEqual(get_key_name(self.dsa_key), "dsa")
        self.assertEqual(get_key_name(self.dsa_key.public_key()), "dsa")
        self.assertEqual(get_key_name(self.dh_key), "dh")
        self.assertEqual(get_key_name(self.dh_key.public_key()), "dh")

    def test_public_key_from_spki(self):
        """
        GIVEN the SubjectPublicKeyInfo of a DSA and a DH public key.
        WHEN the public key is loaded.
        THEN the equal `keyutils_py` public key is returned.
        """
        for key in (self.dsa_key, self.dh_key):
            with self.subTest(key=type(key).__name__):
                spki = subject_public_key_info_from_pubkey(key.public_key())
                self.assertEqual(load_public_key_from_spki(spki), key.public_key())

    def test_save_and_load_key(self):
        """
        GIVEN a DSA and a DH key.
        WHEN the key is saved to a file, with and without a password, and loaded.
        THEN the equal `keyutils_py` key is returned.
        """
        with tempfile.TemporaryDirectory() as directory:
            for key in (self.dsa_key, self.dh_key):
                for password in (None, "11111"):
                    with self.subTest(key=type(key).__name__, password=password):
                        path = os.path.join(directory, "key.pem")
                        save_key(key, path, password=password)
                        loaded = load_private_key_from_file(path, password=password)
                        self.assertIsInstance(loaded, type(key))
                        self.assertEqual(loaded, key)


if __name__ == "__main__":
    unittest.main()
