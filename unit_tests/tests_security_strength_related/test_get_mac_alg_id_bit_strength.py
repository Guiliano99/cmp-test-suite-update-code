# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
import unittest

from pyasn1_alt_modules import rfc5280, rfc9481

from resources.security_utils import get_mac_alg_id_bit_strength
from resources.prepare_alg_ids import prepare_hmac_alg_id, prepare_kmac_alg_id, prepare_pbmac1_parameters
from resources.exceptions import BadAlg


class TestGetMacAlgIdBitStrength(unittest.TestCase):
    """Test suite for get_mac_alg_id_bit_strength function."""

    def test_hmac_sha1_strength(self):
        """
        GIVEN an HMAC-SHA1 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 80 bits.
        """
        alg_id = prepare_hmac_alg_id("sha1")
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 80)

    def test_hmac_sha224_strength(self):
        """
        GIVEN an HMAC-SHA224 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 112 bits.
        """
        alg_id = prepare_hmac_alg_id("sha224")
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 112)

    def test_hmac_sha256_strength(self):
        """
        GIVEN an HMAC-SHA256 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = prepare_hmac_alg_id("sha256")
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_hmac_sha384_strength(self):
        """
        GIVEN an HMAC-SHA384 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 192 bits.
        """
        alg_id = prepare_hmac_alg_id("sha384")
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 192)

    def test_hmac_sha512_strength(self):
        """
        GIVEN an HMAC-SHA512 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = prepare_hmac_alg_id("sha512")
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_hmac_sha3_224_strength(self):
        """
        GIVEN an HMAC-SHA3-224 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 112 bits.
        """
        alg_id = prepare_hmac_alg_id("sha3_224")
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 112)

    def test_hmac_sha3_256_strength(self):
        """
        GIVEN an HMAC-SHA3-256 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = prepare_hmac_alg_id("sha3_256")
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_hmac_sha3_384_strength(self):
        """
        GIVEN an HMAC-SHA3-384 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 192 bits.
        """
        alg_id = prepare_hmac_alg_id("sha3_384")
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 192)

    def test_hmac_sha3_512_strength(self):
        """
        GIVEN an HMAC-SHA3-512 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = prepare_hmac_alg_id("sha3_512")
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_kmac_shake128_strength(self):
        """
        GIVEN a KMAC-SHAKE128 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = prepare_kmac_alg_id("shake128")
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_kmac_shake256_strength(self):
        """
        GIVEN a KMAC-SHAKE256 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = prepare_kmac_alg_id("shake256")
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_pbmac1_sha256_strength(self):
        """
        GIVEN a PBMAC1 AlgorithmIdentifier with SHA256.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits (min of KDF and MAC).
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_PBMAC1
        alg_id["parameters"] = prepare_pbmac1_parameters(
            salt=b"test_salt_12345",
            iterations=10000,
            mac_hash_alg="sha256",
            hash_alg="sha256"
        )
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_pbmac1_sha512_strength(self):
        """
        GIVEN a PBMAC1 AlgorithmIdentifier with SHA512.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits (min of KDF and MAC).
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_PBMAC1
        alg_id["parameters"] = prepare_pbmac1_parameters(
            salt=b"test_salt_12345",
            iterations=10000,
            mac_hash_alg="sha512",
            hash_alg="sha512"
        )
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_pbmac1_mixed_strength(self):
        """
        GIVEN a PBMAC1 AlgorithmIdentifier with SHA256 KDF and SHA512 MAC.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits (minimum of the two).
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_PBMAC1
        alg_id["parameters"] = prepare_pbmac1_parameters(
            salt=b"test_salt_12345",
            iterations=10000,
            mac_hash_alg="sha512",
            hash_alg="sha256"
        )
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_gmac_128_security_strength(self):
        """
        GIVEN a GMAC-128 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_aes128_GMAC
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_gmac_192_security_strength(self):
        """
        GIVEN a GMAC-192 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 192 bits.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_aes192_GMAC
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 192)

    def test_gmac_256_security_strength(self):
        """
        GIVEN a GMAC-256 AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_aes256_GMAC
        strength = get_mac_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_unsupported_mac_algorithm(self):
        """
        GIVEN an unsupported MAC AlgorithmIdentifier.
        WHEN get_mac_alg_id_bit_strength is called,
        THEN a BadAlg exception is raised.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = "1.2.3.4.5.6.7.8.9"  # Non-existent OID
        with self.assertRaises(BadAlg):
            get_mac_alg_id_bit_strength(alg_id)


if __name__ == "__main__":
    unittest.main()
