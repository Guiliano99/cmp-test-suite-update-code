# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from pyasn1_alt_modules.rfc4055 import id_sha256, id_sha512

from resources import other_cert_utils
from unit_tests.utils_for_test import build_certificate


class TestPrepareObjectDigestInfo(unittest.TestCase):
    """Test for preparing the ObjectDigestInfo structure."""

    def test_prepare_object_digest_info_from_certificate_sha256(self):
        """
        GIVEN a CMPCertificate.
        WHEN prepare_object_digest_info is called with hash_alg='sha256'.
        THEN the returned ObjectDigestInfo object contains the correct digest algorithm,
        object type 'publicKeyCert', and digest of the certificate.
        """
        cert, _ = build_certificate("rsa")

        result = other_cert_utils.prepare_object_digest_info(cert, hash_alg="sha256")

        self.assertEqual(result['digestedObjectType'], 1)
        self.assertTrue(result['digestAlgorithm'].isValue)
        self.assertEqual(result['digestAlgorithm']['algorithm'], id_sha256)
        self.assertTrue(result['objectDigest'].isValue)
        self.assertEqual(len(result['objectDigest'].asOctets()), 32)

    def test_prepare_object_digest_info_from_certificate_sha512(self):
        """
        GIVEN a CMPCertificate.
        WHEN prepare_object_digest_info is called with hash_alg='sha512'.
        THEN the returned ObjectDigestInfo object contains the correct digest algorithm,
        object type 'publicKeyCert', and digest of the certificate.
        """
        cert, _ = build_certificate("rsa")

        result = other_cert_utils.prepare_object_digest_info(cert, hash_alg="sha512")

        self.assertEqual(result['digestedObjectType'], 1)
        self.assertTrue(result['digestAlgorithm'].isValue)
        self.assertEqual(result['digestAlgorithm']['algorithm'], id_sha512)
        self.assertTrue(result['objectDigest'].isValue)
        self.assertEqual(len(result['objectDigest'].asOctets()), 64)

    def test_prepare_object_digest_info_from_public_key(self):
        """
        GIVEN a public key (from a certificate).
        WHEN prepare_object_digest_info is called.
        THEN the returned ObjectDigestInfo object contains the correct digest algorithm,
        object type 'publicKey', and digest of the public key.
        """
        cert, key = build_certificate("rsa")

        result = other_cert_utils.prepare_object_digest_info(key.public_key(), hash_alg="sha256")

        self.assertEqual(result['digestedObjectType'], 0)
        self.assertTrue(result['digestAlgorithm'].isValue)
        self.assertEqual(result['digestAlgorithm']['algorithm'], id_sha256)
        self.assertTrue(result['objectDigest'].isValue)

    def test_prepare_object_digest_info_with_bad_digest(self):
        """
        GIVEN a CMPCertificate.
        WHEN prepare_object_digest_info is called with bad_digest=True.
        THEN the returned ObjectDigestInfo object contains an incorrect digest value.
        """
        cert, _ = build_certificate("rsa")

        result_good = other_cert_utils.prepare_object_digest_info(cert, hash_alg="sha256", bad_digest=False)
        result_bad = other_cert_utils.prepare_object_digest_info(cert, hash_alg="sha256", bad_digest=True)

        self.assertNotEqual(result_good['objectDigest'], result_bad['objectDigest'])
        self.assertEqual(result_good['digestedObjectType'], result_bad['digestedObjectType'])

    def test_prepare_object_digest_info_from_der_data(self):
        """
        GIVEN DER-encoded data.
        WHEN prepare_object_digest_info is called with der_data parameter.
        THEN the returned ObjectDigestInfo object contains the correct digest of the DER data
        with object type 'otherObjectTypes'.
        """
        der_data = b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00'

        result = other_cert_utils.prepare_object_digest_info(None, hash_alg="sha256", der_data=der_data)

        self.assertEqual(result['digestedObjectType'], 2)
        self.assertTrue(result['digestAlgorithm'].isValue)
        self.assertTrue(result['objectDigest'].isValue)

    def test_prepare_object_digest_info_missing_both_params(self):
        """
        GIVEN neither cert_or_pub_key nor der_data.
        WHEN prepare_object_digest_info is called.
        THEN a ValueError is raised.
        """
        with self.assertRaises(ValueError) as context:
            other_cert_utils.prepare_object_digest_info(None, hash_alg="sha256")
        self.assertIn("Either cert_or_pub_key or der_data must be provided", str(context.exception))

    def test_prepare_object_digest_info_both_params_provided(self):
        """
        GIVEN both cert_or_pub_key and der_data.
        WHEN prepare_object_digest_info is called.
        THEN a ValueError is raised.
        """
        cert, _ = build_certificate("rsa")
        der_data = b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00'

        with self.assertRaises(ValueError) as context:
            other_cert_utils.prepare_object_digest_info(cert, hash_alg="sha256", der_data=der_data)
        self.assertIn("Only one of `cert_or_pub_key` or `der_data` can be provided", str(context.exception))

    def test_prepare_object_digest_info_with_ec_key(self):
        """
        GIVEN a certificate with an EC key.
        WHEN prepare_object_digest_info is called.
        THEN the returned ObjectDigestInfo object is correctly created.
        """
        cert, _ = build_certificate("ec")

        result = other_cert_utils.prepare_object_digest_info(cert, hash_alg="sha256")

        self.assertEqual(result['digestedObjectType'], 1)
        self.assertTrue(result['digestAlgorithm'].isValue)
        self.assertTrue(result['objectDigest'].isValue)

    def test_prepare_object_digest_info_with_ed25519_key(self):
        """
        GIVEN a certificate with an Ed25519 key.
        WHEN prepare_object_digest_info is called.
        THEN the returned ObjectDigestInfo object is correctly created.
        """
        cert, _ = build_certificate("ed25519")

        result = other_cert_utils.prepare_object_digest_info(cert, hash_alg="sha256")

        self.assertEqual(result['digestedObjectType'], 1)
        self.assertTrue(result['digestAlgorithm'].isValue)
        self.assertTrue(result['objectDigest'].isValue)


if __name__ == '__main__':
    unittest.main()

