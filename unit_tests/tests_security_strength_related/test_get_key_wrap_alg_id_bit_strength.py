# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
import unittest

from pyasn1_alt_modules import rfc5280, rfc9481

from resources.exceptions import BadAlg
from resources.security_utils import get_key_wrap_alg_id_bit_strength


class TestGetKeyWrapAlgIdBitStrength(unittest.TestCase):
    """Tests for get_key_wrap_alg_id_bit_strength function."""

    def test_aes256_key_wrap_strength(self):
        """
        GIVEN an AES-256 Key Wrap AlgorithmIdentifier.
        WHEN get_key_wrap_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_aes256_wrap
        strength = get_key_wrap_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_aes192_key_wrap_strength(self):
        """
        GIVEN an AES-192 Key Wrap AlgorithmIdentifier.
        WHEN get_key_wrap_alg_id_bit_strength is called,
        THEN the returned security strength is 192 bits.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_aes192_wrap
        strength = get_key_wrap_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 192)

    def test_aes128_key_wrap_strength(self):
        """
        GIVEN an AES-128 Key Wrap AlgorithmIdentifier.
        WHEN get_key_wrap_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_aes128_wrap
        strength = get_key_wrap_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_unknown_key_wrap_alg(self):
        """
        GIVEN an unknown Key Wrap AlgorithmIdentifier.
        WHEN get_key_wrap_alg_id_bit_strength is called,
        THEN a BadAlg exception is raised.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_aes128_CBC
        with self.assertRaises(BadAlg):
            get_key_wrap_alg_id_bit_strength(alg_id)


if __name__ == "__main__":
    unittest.main()