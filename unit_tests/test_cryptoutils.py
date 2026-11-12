# Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9481

from resources import cryptoutils


class TestCryptoUtils(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # used for testing PBMAC1
        cls.predefined_salt = b"1234567890abcdef"

    def test_compute_pbmac1(self):
        """
        GIVEN a message, a key, and a salt.
        WHEN the compute_pbmac1 function is called,
        THEN the result should be the expected MAC.
        """
        mac = cryptoutils.compute_pbmac1(b"hello", b"key", hash_alg="sha512", salt=self.predefined_salt)
        self.assertEqual(
            mac,
            b"\xc3\xe7\xe5S\xa9<mq(j\xda\x95\x11\x86\xf9\xae$l\x14\x84L\x89\xef\x10\xd21vZa\x1c\xf2\x04A\x9d\x940\x0e\x8f&\xd2\x1fDj=\xaf\xb8B\xc8\x99\xdc\xe2\x8cu\xef;9\xa4\xc2s\xcf\x1d\xcaR\xdc",
        )

    def test_compute_password_based_mac(self):
        """
        GIVEN a password, a key, a salt, and a hash algorithm.
        WHEN the compute_password_based_mac function is called,
        THEN the result should be the expected MAC.
        """
        mac = cryptoutils.compute_password_based_mac(
            b"hello", b"key", iterations=5, salt=self.predefined_salt, hash_alg="sha256"
        )
        self.assertEqual(
            mac, b"\xa8$\xe6\x00\x19\xa1\xd2\x1eX\x0f\xb3`\xe9vp\xa6\xbd'\"B\x9a\xfe\xaf\xa7I\x00d\xe3\xb1\x91\n\xf3"
        )

    def test_prepare_ecc_cms_shared_info_none_uses_kek_length_in_bits(self):
        """
        GIVEN the AES-128, AES-192 and AES-256 key-wrap OIDs.
        WHEN `prepare_ecc_cms_shared_info` is called with `supp_pub_info=None`.
        THEN the DER-encoded `ECC-CMS-SharedInfo` must carry the KEK length in bits as a 32-bit number
        in `suppPubInfo` (RFC 5753 Section 7.2, e.g. 00 00 01 00 for AES-256), matching the hand-built DER.
        """
        # SEQUENCE { SEQUENCE { wrap OID (absent parameters) }, [2] EXPLICIT OCTET STRING (4 octets) }
        expected = [
            (rfc9481.id_aes128_wrap, "3015300b0609608648016503040105a206040400000080"),
            (rfc9481.id_aes192_wrap, "3015300b0609608648016503040119a2060404000000c0"),
            (rfc9481.id_aes256_wrap, "3015300b060960864801650304012da206040400000100"),
        ]
        for key_wrap_oid, der_hex in expected:
            with self.subTest(key_wrap_oid=str(key_wrap_oid)):
                shared_info = cryptoutils.prepare_ecc_cms_shared_info(key_wrap_oid=key_wrap_oid, supp_pub_info=None)
                self.assertEqual(encoder.encode(shared_info).hex(), der_hex)


if __name__ == "__main__":
    unittest.main()
