# Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import base64
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.codec.der import decoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3565, rfc5208, rfc8018

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

    def test_encrypt_private_key_pkcs8_roundtrip(self):
        """
        GIVEN a private key DER bytes and password,
        WHEN encrypt_private_key_pkcs8 is called followed by decrypt_private_key_pkcs8,
        THEN the decrypted DER bytes match the original key.
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        password = b"test-password"
        pem = cryptoutils.encrypt_private_key_pkcs8(private_key_der, password=password, iterations=1000)
        decrypted_der = cryptoutils.decrypt_private_key_pkcs8(pem, password=password)
        loaded_key = serialization.load_der_private_key(decrypted_der, password=None)
        self.assertEqual(loaded_key.private_numbers(), private_key.private_numbers())

    def test_encrypt_private_key_pkcs8_structure(self):
        """
        GIVEN a private key DER bytes and password,
        WHEN encrypt_private_key_pkcs8 is called,
        THEN the ASN.1 structure uses PBES2 with PBKDF2 and AES-256-CBC.
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        password = b"test-password"
        pem = cryptoutils.encrypt_private_key_pkcs8(private_key_der, password=password, iterations=1000)

        pem_lines = [
            line for line in pem.decode("ascii").splitlines() if "BEGIN ENCRYPTED PRIVATE KEY" not in line
        ]
        pem_lines = [line for line in pem_lines if "END ENCRYPTED PRIVATE KEY" not in line]
        der = base64.b64decode("".join(pem_lines))

        enc_info, rest = decoder.decode(der, rfc5208.EncryptedPrivateKeyInfo())
        self.assertFalse(rest)
        self.assertEqual(enc_info["encryptionAlgorithm"]["algorithm"], rfc8018.id_PBES2)

        pbes2_params, rest = decoder.decode(enc_info["encryptionAlgorithm"]["parameters"], rfc8018.PBES2_params())
        self.assertFalse(rest)
        self.assertEqual(pbes2_params["keyDerivationFunc"]["algorithm"], rfc8018.id_PBKDF2)

        pbkdf2_params = pbes2_params["keyDerivationFunc"]["parameters"]
        if not isinstance(pbkdf2_params, rfc8018.PBKDF2_params):
            pbkdf2_params, rest = decoder.decode(pbkdf2_params, rfc8018.PBKDF2_params())
            self.assertFalse(rest)
        self.assertEqual(int(pbkdf2_params["iterationCount"]), 1000)
        self.assertEqual(len(pbkdf2_params["salt"]["specified"].asOctets()), 16)

        self.assertEqual(pbes2_params["encryptionScheme"]["algorithm"], rfc3565.id_aes256_CBC)
        iv_param = pbes2_params["encryptionScheme"]["parameters"]
        if isinstance(iv_param, univ.Any):
            iv_param, rest = decoder.decode(iv_param, univ.OctetString())
            self.assertFalse(rest)
        self.assertEqual(len(iv_param.asOctets()), 16)


if __name__ == "__main__":
    unittest.main()
