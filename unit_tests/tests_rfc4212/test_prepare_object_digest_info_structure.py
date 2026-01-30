# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from pyasn1.type import univ, tag
from pyasn1_alt_modules import rfc5280, rfc5755
from pyasn1_alt_modules.rfc5480 import id_sha256

from resources import other_cert_utils
from resources.asn1utils import try_decode_pyasn1
from unit_tests.utils_for_test import try_encode_pyasn1

class TestPrepareObjectDigestInfoStructure(unittest.TestCase):
    def test_prepare_object_digest_info_publickey(self):
        """
        GIVEN a digest algorithm, object type 'publickey', and a digest.
        WHEN prepare_object_digest_info is called.
        THEN the returned ObjectDigestInfo object contains the correct digest algorithm, object type, and digest.
        """
        digest_alg = rfc5280.AlgorithmIdentifier()
        digest_alg['algorithm'] = id_sha256
        object_type = "publickey"
        digest = b'\x00' * 32
        
        result = other_cert_utils.prepare_object_digest_info_structure(digest_alg, object_type, digest)
        
        self.assertEqual(result['digestedObjectType'], 0)
        self.assertEqual(result['objectDigest'], univ.BitString.fromOctetString(digest))

        der_data = try_encode_pyasn1(result)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.ObjectDigestInfo().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 2)))
        self.assertEqual(rest, b"")

    def test_prepare_object_digest_info_cert(self):
        """
        GIVEN a digest algorithm, object type 'publicKeyCert', and a digest.
        WHEN prepare_object_digest_info is called.
        THEN the returned ObjectDigestInfo object contains the correct digest algorithm, object type, and digest.
        """
        digest_alg = rfc5280.AlgorithmIdentifier()
        digest_alg['algorithm'] = id_sha256
        object_type = "publicKeyCert"
        digest = b'\x00' * 32
        
        result = other_cert_utils.prepare_object_digest_info_structure(digest_alg, object_type, digest)
        
        self.assertEqual(result['digestedObjectType'], 1)

        der_data = try_encode_pyasn1(result)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.ObjectDigestInfo().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 2)))
        self.assertEqual(rest, b"")

    def test_prepare_object_digest_info_other(self):
        """
        GIVEN a digest algorithm, object type 'otherObjectTypes', a digest, and an other object type ID.
        WHEN prepare_object_digest_info is called.
        THEN the returned ObjectDigestInfo object contains the correct digest algorithm, object type, digest, and other object type ID.
        """
        digest_alg = rfc5280.AlgorithmIdentifier()
        digest_alg['algorithm'] = id_sha256
        object_type = "otherObjectTypes"
        digest = b'\x00' * 32
        other_oid = univ.ObjectIdentifier('1.2.3.4')
        
        result = other_cert_utils.prepare_object_digest_info_structure(
            digest_alg, object_type, digest, other_object_type_id=other_oid
        )
        
        self.assertEqual(result['digestedObjectType'], 2)
        self.assertEqual(result['otherObjectTypeID'], other_oid)

        der_data = try_encode_pyasn1(result)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.ObjectDigestInfo().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 2)))
        self.assertEqual(rest, b"")

    def test_prepare_object_digest_info_negative(self):
        """
        GIVEN a digest algorithm, an invalid object type, and a digest.
        WHEN prepare_object_digest_info is called.
        THEN a ValueError is raised.
        """
        digest_alg = rfc5280.AlgorithmIdentifier()
        digest = b'\x00' * 32
        
        with self.assertRaises(ValueError):
            other_cert_utils.prepare_object_digest_info_structure(digest_alg, "invalid_type", digest)

if __name__ == '__main__':
    unittest.main()
