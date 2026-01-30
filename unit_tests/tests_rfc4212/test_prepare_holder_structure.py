# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from pyasn1.type import tag
from pyasn1_alt_modules import rfc4212, rfc9480, rfc5280
from pyasn1_alt_modules.rfc5480 import id_sha256

from resources import other_cert_utils
from resources.asn1utils import try_decode_pyasn1
from resources.prepareutils import prepare_name
from unit_tests.utils_for_test import try_encode_pyasn1


class TestPrepareHolderStructure(unittest.TestCase):
    """Test the preparation of the Holder structure."""

    def test_prepare_holder_with_base_cert_id_issuer_serial(self):
        """
        GIVEN an IssuerSerial structure as base_certificate_id.
        WHEN prepare_holder_structure is called.
        THEN the returned Holder object contains the correct baseCertificateID
        and can be encoded and decoded.
        """
        # Prepare an IssuerSerial
        issuer = "CN=Test Issuer"
        serial_number = 12345
        issuer_serial = other_cert_utils.prepare_issuer_serial_structure(issuer, serial_number)

        holder = other_cert_utils.prepare_holder(base_certificate_id=issuer_serial)

        self.assertTrue(holder["baseCertificateID"].isValue)
        self.assertEqual(int(holder["baseCertificateID"]["serial"]), serial_number)
        self.assertFalse(holder["entityName"].isValue)
        self.assertFalse(holder["objectDigestInfo"].isValue)

        der_data = try_encode_pyasn1(holder)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc4212.Holder().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
        self.assertEqual(rest, b"")

    def test_prepare_holder_with_base_cert_id_certificate(self):
        """
        GIVEN a CMPCertificate as base_certificate_id.
        WHEN prepare_holder_structure is called.
        THEN the returned Holder object contains the baseCertificateID derived from the certificate
        and can be encoded and decoded.
        """
        # Create a minimal certificate
        cert = rfc9480.CMPCertificate()
        tbs = cert['tbsCertificate']
        tbs['serialNumber'] = 54321
        tbs["issuer"] = prepare_name("CN=Certificate Issuer")

        # Prepare Holder with certificate
        holder = other_cert_utils.prepare_holder(base_certificate_id=cert)

        self.assertTrue(holder["baseCertificateID"].isValue)
        self.assertEqual(int(holder["baseCertificateID"]["serial"]), 54321)
        self.assertFalse(holder["entityName"].isValue)
        self.assertFalse(holder["objectDigestInfo"].isValue)

        der_data = try_encode_pyasn1(holder)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc4212.Holder().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
        self.assertEqual(rest, b"")

    def test_prepare_holder_with_entity_name(self):
        """
        GIVEN an entity name as a string.
        WHEN prepare_holder_structure is called.
        THEN the returned Holder object contains the correct entityName
        and can be encoded and decoded.
        """
        entity_name = "CN=Entity Name"

        holder = other_cert_utils.prepare_holder(entity_name=entity_name)

        self.assertFalse(holder["baseCertificateID"].isValue)
        self.assertTrue(holder["entityName"].isValue)
        self.assertFalse(holder["objectDigestInfo"].isValue)

        der_data = try_encode_pyasn1(holder)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc4212.Holder().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
        self.assertEqual(rest, b"")

    def test_prepare_holder_with_object_digest_info(self):
        """
        GIVEN an ObjectDigestInfo structure.
        WHEN prepare_holder_structure is called.
        THEN the returned Holder object contains the correct objectDigestInfo
        and can be encoded and decoded.
        """
        digest_alg = rfc5280.AlgorithmIdentifier()
        digest_alg['algorithm'] = id_sha256  # SHA-256
        object_type = "publickey"
        digest = b'\x01\x02\x03\x04' * 8  # 32 bytes

        object_digest_info = other_cert_utils.prepare_object_digest_info_structure(
            digest_alg, object_type, digest
        )

        holder = other_cert_utils.prepare_holder(object_digest_info=object_digest_info)

        self.assertFalse(holder["baseCertificateID"].isValue)
        self.assertFalse(holder["entityName"].isValue)
        self.assertTrue(holder["objectDigestInfo"].isValue)
        self.assertEqual(holder["objectDigestInfo"]["digestedObjectType"], 0)

        der_data = try_encode_pyasn1(holder)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc4212.Holder().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
        self.assertEqual(rest, b"")

    def test_prepare_holder_with_all_fields(self):
        """
        GIVEN all three fields: base_certificate_id, entity_name, and object_digest_info.
        WHEN prepare_holder_structure is called.
        THEN the returned Holder object contains all fields populated
        and can be encoded and decoded.
        """
        issuer = "CN=Test Issuer"
        serial_number = 99999
        issuer_serial = other_cert_utils.prepare_issuer_serial_structure(issuer, serial_number)

        entity_name = "CN=Entity Name"

        digest_alg = rfc5280.AlgorithmIdentifier()
        digest_alg['algorithm'] = id_sha256
        object_type = "publicKeyCert"
        digest = b'\xaa\xbb\xcc\xdd' * 8
        object_digest_info = other_cert_utils.prepare_object_digest_info_structure(
            digest_alg, object_type, digest
        )

        holder = other_cert_utils.prepare_holder(
            base_certificate_id=issuer_serial,
            entity_name=entity_name,
            object_digest_info=object_digest_info
        )

        self.assertTrue(holder["baseCertificateID"].isValue)
        self.assertTrue(holder["entityName"].isValue)
        self.assertTrue(holder["objectDigestInfo"].isValue)

        der_data = try_encode_pyasn1(holder)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc4212.Holder().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
        self.assertEqual(rest, b"")

    def test_prepare_holder_with_target(self):
        """
        GIVEN a target Holder object with custom tagging and an IssuerSerial.
        WHEN prepare_holder_structure is called with the target.
        THEN the returned object is the target object populated with the correct data
        and can be encoded and decoded with the custom tag.
        """
        # Create a target with custom tagging
        target = rfc4212.Holder().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 5))

        issuer = "CN=Target Test"
        serial_number = 77777
        issuer_serial = other_cert_utils.prepare_issuer_serial_structure(issuer, serial_number)

        holder = other_cert_utils.prepare_holder(
            base_certificate_id=issuer_serial,
            target=target
        )

        self.assertIs(holder, target)
        self.assertTrue(holder["baseCertificateID"].isValue)

        der_data = try_encode_pyasn1(holder)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc4212.Holder().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5)))
        self.assertEqual(rest, b"")

    def test_prepare_holder_empty(self):
        """
        GIVEN no parameters (all optional fields are None).
        WHEN prepare_holder_structure is called.
        THEN the returned Holder object has no fields populated
        and can be encoded and decoded.
        """
        holder = other_cert_utils.prepare_holder()

        self.assertFalse(holder["baseCertificateID"].isValue)
        self.assertFalse(holder["entityName"].isValue)
        self.assertFalse(holder["objectDigestInfo"].isValue)

        der_data = try_encode_pyasn1(holder)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc4212.Holder().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
        self.assertEqual(rest, b"")

    def test_prepare_holder_invalid_base_cert_id_type(self):
        """
        GIVEN an invalid type for base_certificate_id (not IssuerSerial or CMPCertificate).
        WHEN prepare_holder_structure is called.
        THEN a TypeError is raised.
        """
        with self.assertRaises(TypeError) as context:
            other_cert_utils.prepare_holder(base_certificate_id="invalid_type")  # type: ignore

        self.assertIn("Invalid baseCertificateID type", str(context.exception))


if __name__ == '__main__':
    unittest.main()
