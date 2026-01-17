# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
import unittest

from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280

from resources.security_utils import get_kdf_alg_id_bit_strength
from resources.prepare_alg_ids import prepare_kdf_alg_id
from resources.exceptions import BadAlg


class TestGetKdfAlgIdBitStrength(unittest.TestCase):
    """Test suite for get_kdf_alg_id_bit_strength function."""

    # KDF2 Tests
    def test_kdf2_sha1_strength(self):
        """
        GIVEN a KDF2-SHA1 AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 80 bits.
        """
        alg_id = prepare_kdf_alg_id("kdf2", hash_alg="sha1")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 80)

    def test_kdf2_sha224_strength(self):
        """
        GIVEN a KDF2-SHA224 AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 112 bits.
        """
        alg_id = prepare_kdf_alg_id("kdf2", hash_alg="sha224")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 112)

    def test_kdf2_sha256_strength(self):
        """
        GIVEN a KDF2-SHA256 AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = prepare_kdf_alg_id("kdf2", hash_alg="sha256")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_kdf2_sha384_strength(self):
        """
        GIVEN a KDF2-SHA384 AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 192 bits.
        """
        alg_id = prepare_kdf_alg_id("kdf2", hash_alg="sha384")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 192)

    def test_kdf2_sha512_strength(self):
        """
        GIVEN a KDF2-SHA512 AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = prepare_kdf_alg_id("kdf2", hash_alg="sha512")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    # KDF3 Tests
    def test_kdf3_sha256_strength(self):
        """
        GIVEN a KDF3-SHA256 AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = prepare_kdf_alg_id("kdf3", hash_alg="sha256")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_kdf3_sha384_strength(self):
        """
        GIVEN a KDF3-SHA384 AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 192 bits.
        """
        alg_id = prepare_kdf_alg_id("kdf3", hash_alg="sha384")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 192)

    def test_kdf3_sha512_strength(self):
        """
        GIVEN a KDF3-SHA512 AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = prepare_kdf_alg_id("kdf3", hash_alg="sha512")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    # HKDF Tests
    def test_hkdf_sha256_strength(self):
        """
        GIVEN an HKDF-SHA256 AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = prepare_kdf_alg_id("hkdf", hash_alg="sha256")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_hkdf_sha384_strength(self):
        """
        GIVEN an HKDF-SHA384 AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 192 bits.
        """
        alg_id = prepare_kdf_alg_id("hkdf", hash_alg="sha384")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 192)

    def test_hkdf_sha512_strength(self):
        """
        GIVEN an HKDF-SHA512 AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = prepare_kdf_alg_id("hkdf", hash_alg="sha512")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    # PBKDF2 Tests
    def test_pbkdf2_sha256_key32_strength(self):
        """
        GIVEN a PBKDF2-SHA256 AlgorithmIdentifier with 32-byte key length.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits (min of hash and key length).
        """
        alg_id = prepare_kdf_alg_id("pbkdf2", salt=b"test_salt_12345", iterations=10000, length=32, hash_alg="sha256")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_pbkdf2_sha256_key16_strength(self):
        """
        GIVEN a PBKDF2-SHA256 AlgorithmIdentifier with 16-byte key length.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits (min of 128-bit hash and 128-bit key).
        """
        alg_id = prepare_kdf_alg_id("pbkdf2", salt=b"test_salt_12345", iterations=10000, length=16, hash_alg="sha256")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_pbkdf2_sha512_key32_strength(self):
        """
        GIVEN a PBKDF2-SHA512 AlgorithmIdentifier with 32-byte key length.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits (min of 256-bit hash and 256-bit key).
        """
        alg_id = prepare_kdf_alg_id("pbkdf2", salt=b"test_salt_12345", iterations=10000, length=32, hash_alg="sha512")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_pbkdf2_sha512_key64_strength(self):
        """
        GIVEN a PBKDF2-SHA512 AlgorithmIdentifier with 64-byte key length.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits (min of 256-bit hash and 512-bit key).
        """
        alg_id = prepare_kdf_alg_id("pbkdf2", salt=b"test_salt_12345", iterations=10000, length=64, hash_alg="sha512")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_pbkdf2_sha384_key48_strength(self):
        """
        GIVEN a PBKDF2-SHA384 AlgorithmIdentifier with 48-byte key length.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 192 bits (min of 192-bit hash and 384-bit key).
        """
        alg_id = prepare_kdf_alg_id("pbkdf2", salt=b"test_salt_12345", iterations=10000, length=48, hash_alg="sha384")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 192)

    def test_pbkdf2_sha256_key64_strength(self):
        """
        GIVEN a PBKDF2-SHA256 AlgorithmIdentifier with 64-byte key length.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits (limited by hash strength).
        """
        alg_id = prepare_kdf_alg_id("pbkdf2", salt=b"test_salt_12345", iterations=10000, length=64, hash_alg="sha256")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_pbkdf2_sha3_256_strength(self):
        """
        GIVEN a PBKDF2-SHA3-256 AlgorithmIdentifier with 32-byte key length.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = prepare_kdf_alg_id("pbkdf2", salt=b"test_salt_12345", iterations=10000, length=32, hash_alg="sha3_256")
        strength = get_kdf_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_unsupported_kdf_algorithm(self):
        """
        GIVEN an unsupported KDF AlgorithmIdentifier.
        WHEN get_kdf_alg_id_bit_strength is called,
        THEN a BadAlg exception is raised.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = univ.ObjectIdentifier("1.2.3.4.5.6.7.8.9")  # Non-existent KDF-OID
        with self.assertRaises(BadAlg):
            get_kdf_alg_id_bit_strength(alg_id)


if __name__ == "__main__":
    unittest.main()
