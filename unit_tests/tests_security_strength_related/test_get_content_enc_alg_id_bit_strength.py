# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
import unittest

from pyasn1_alt_modules import rfc5280, rfc9481

from resources.security_utils import get_content_enc_alg_id_bit_strength
from resources.exceptions import BadAlg

class TestGetContentEncAlgIdBitStrength(unittest.TestCase):
    """Tests for get_content_enc_alg_id_bit_strength function."""

    def test_aes256_cbc_content_enc_strength(self):
        """
        GIVEN an AES-256-CBC Content Encryption AlgorithmIdentifier.
        WHEN get_content_enc_alg_id_bit_strength is called,
        THEN the returned security strength is 256 bits.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_aes256_CBC
        strength = get_content_enc_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 256)

    def test_aes192_cbc_content_enc_strength(self):
        """
        GIVEN an AES-192-CBC Content Encryption AlgorithmIdentifier.
        WHEN get_content_enc_alg_id_bit_strength is called,
        THEN the returned security strength is 192 bits.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_aes192_CBC
        strength = get_content_enc_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 192)

    def test_aes128_cbc_content_enc_strength(self):
        """
        GIVEN an AES-128-CBC Content Encryption AlgorithmIdentifier.
        WHEN get_content_enc_alg_id_bit_strength is called,
        THEN the returned security strength is 128 bits.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_aes128_CBC
        strength = get_content_enc_alg_id_bit_strength(alg_id)
        self.assertEqual(strength, 128)

    def test_unknown_content_enc_alg(self):
        """
        GIVEN an unknown Content Encryption AlgorithmIdentifier.
        WHEN get_content_enc_alg_id_bit_strength is called,
        THEN a BadAlg exception is raised.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.id_aes256_wrap
        with self.assertRaises(BadAlg):
            get_content_enc_alg_id_bit_strength(alg_id)

if __name__ == "__main__":
    unittest.main()
