# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
import unittest

from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc9481

from resources.security_utils import get_hash_alg_id_bit_strength
from resources.exceptions import BadAlg
from resources.prepare_alg_ids import prepare_sha_alg_id


class TestGetHashAlgIdBitStrength(unittest.TestCase):
    """Test suite for get_hash_alg_id_bit_strength function."""

    def test_sha1_strength(self):
        """
        GIVEN an SHA-1 AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN the returned security strength is 80 bits.
        """
        alg_id = prepare_sha_alg_id("sha1")
        strength = get_hash_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 80)

    def test_sha224_strength(self):
        """
        GIVEN an SHA-224 AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN the returned security strength is 112 bits.
        """
        alg_id = prepare_sha_alg_id("sha224")
        strength = get_hash_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 112)

    def test_sha256_strength(self):
        """
        GIVEN an SHA-256 AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = prepare_sha_alg_id("sha256")
        strength = get_hash_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_sha384_strength(self):
        """
        GIVEN an SHA-384 AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN the returned security strength is 192 bits.
        """
        alg_id = prepare_sha_alg_id("sha384")
        strength = get_hash_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 192)

    def test_sha512_strength(self):
        """
        GIVEN an SHA-512 AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = prepare_sha_alg_id("sha512")
        strength = get_hash_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_sha3_224_strength(self):
        """
        GIVEN an SHA3-224 AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN the returned security strength is 112 bits.
        """
        alg_id = prepare_sha_alg_id("sha3_224")
        strength = get_hash_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 112)

    def test_sha3_256_strength(self):
        """
        GIVEN an SHA3-256 AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = prepare_sha_alg_id("sha3_256")
        strength = get_hash_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_sha3_384_strength(self):
        """
        GIVEN an SHA3-384 AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN the returned security strength is 192 bits.
        """
        alg_id = prepare_sha_alg_id("sha3_384")
        strength = get_hash_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 192)

    def test_sha3_512_strength(self):
        """
        GIVEN an SHA3-512 AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = prepare_sha_alg_id("sha3_512")
        strength = get_hash_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_shake128_strength(self):
        """
        GIVEN an SHAKE128 AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = prepare_sha_alg_id("shake128")
        strength = get_hash_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_shake256_strength(self):
        """
        GIVEN an SHAKE256 AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = prepare_sha_alg_id("shake256")
        strength = get_hash_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_unsupported_hash_algorithm(self):
        """
        GIVEN an unsupported hash AlgorithmIdentifier.
        WHEN get_hash_alg_id_bit_strength is called,
        THEN a BadAlg exception is raised.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_ecdsa_with_shake128
        alg_id["parameters"] = univ.Null("")
        with self.assertRaises(BadAlg):
            get_hash_alg_id_bit_strength(alg_id)


if __name__ == "__main__":
    unittest.main()
