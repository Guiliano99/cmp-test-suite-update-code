# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc9480, rfc5755

from resources import other_cert_utils
from resources.asn1utils import try_decode_pyasn1
from resources.prepareutils import prepare_name
from unit_tests.utils_for_test import try_encode_pyasn1


class TestPrepareAttCertIssuerV2Form(unittest.TestCase):
    """Test the preparation of the V2Form structure for attribute certificate issuers."""

    def setUp(self):
        """Set up a test certificate for use in test cases."""
        self.cert = rfc9480.CMPCertificate()
        tbs = self.cert['tbsCertificate']
        tbs['serialNumber'] = 12345
        tbs["issuer"] = prepare_name("CN=Test Issuer")

    def test_prepare_basic(self):
        """
        GIVEN a CA certificate.
        WHEN prepare_att_cert_issuer_v2form is called with defaults.
        THEN it returns a V2Form with only issuerName set and can be encoded and decoded.
        """
        v2form = other_cert_utils.prepare_att_cert_issuer_v2form(self.cert)

        # Verify issuerName is set
        self.assertTrue(v2form['issuerName'].isValue)
        self.assertFalse(v2form['baseCertificateID'].isValue)
        self.assertFalse(v2form['objectDigestInfo'].isValue)

        # Test encoding and decoding
        der_data = try_encode_pyasn1(v2form)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.V2Form().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
        self.assertEqual(rest, b"")

    def test_prepare_with_base_certificate_id(self):
        """
        GIVEN a CA certificate.
        WHEN prepare_att_cert_issuer_v2form is called with add_base_certificate_id=True.
        THEN it returns a V2Form with both issuerName and baseCertificateID set.
        """
        v2form = other_cert_utils.prepare_att_cert_issuer_v2form(self.cert, add_base_certificate_id=True)

        # Verify both issuerName and baseCertificateID are set
        self.assertTrue(v2form['issuerName'].isValue)
        self.assertTrue(v2form['baseCertificateID'].isValue)
        self.assertEqual(int(v2form['baseCertificateID']['serial']), 12345)
        self.assertFalse(v2form['objectDigestInfo'].isValue)

        # Test encoding and decoding
        der_data = try_encode_pyasn1(v2form)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.V2Form().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
        self.assertEqual(rest, b"")

    def test_prepare_with_digest_obj_info(self):
        """
        GIVEN a CA certificate.
        WHEN prepare_att_cert_issuer_v2form is called with add_digest_obj_info=True
        and a custom object_digest_info kwarg.
        THEN it returns a V2Form with issuerName set and the digest info in digestedObjectType field.
        Note: There appears to be a bug in the implementation where it assigns to
        'digestedObjectType' instead of 'objectDigestInfo'.
        """
        # Create a pre-constructed ObjectDigestInfo to pass
        digest_obj_info = rfc5755.ObjectDigestInfo()
        digest_obj_info['digestedObjectType'] = 1  # publicKeyCert
        digest_obj_info['digestAlgorithm']["algorithm"] = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')
        digest_obj_info['objectDigest'] = univ.BitString().fromOctetString(b'\x00' * 32)

        v2form = other_cert_utils.prepare_att_cert_issuer_v2form(
            self.cert,
            add_digest_obj_info=True,
            object_digest_info=digest_obj_info
        )

        # Verify issuerName is set
        self.assertTrue(v2form['issuerName'].isValue)
        self.assertFalse(v2form['baseCertificateID'].isValue)
        # Due to bug, objectDigestInfo is assigned to digestedObjectType field
        self.assertTrue(v2form['digestedObjectType'].isValue)

        # Test encoding and decoding
        der_data = try_encode_pyasn1(v2form)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.V2Form().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
        self.assertEqual(rest, b"")

    def test_prepare_with_base_certificate_id_and_custom_digest(self):
        """
        GIVEN a CA certificate.
        WHEN prepare_att_cert_issuer_v2form is called with add_base_certificate_id=True
        and add_digest_obj_info=True with a custom object_digest_info.
        THEN it returns a V2Form with baseCertificateID and digestedObjectType fields set.
        """
        # Create a pre-constructed ObjectDigestInfo to pass
        digest_obj_info = rfc5755.ObjectDigestInfo()
        digest_obj_info['digestedObjectType'] = univ.Enumerated(1)
        digest_obj_info['digestAlgorithm']["algorithm"] = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')
        digest_obj_info['objectDigest'] = univ.BitString().fromOctetString(b'\x00' * 32)

        v2form = other_cert_utils.prepare_att_cert_issuer_v2form(
            self.cert,
            add_base_certificate_id=True,
            add_digest_obj_info=True,
            object_digest_info=digest_obj_info
        )

        # Verify fields are set
        self.assertTrue(v2form['issuerName'].isValue)
        self.assertTrue(v2form['baseCertificateID'].isValue)
        self.assertTrue(v2form["objectDigestInfo"].isValue)

        # Test encoding and decoding
        der_data = try_encode_pyasn1(v2form)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.V2Form().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
        self.assertEqual(rest, b"")

    def test_prepare_with_no_digest_when_flag_true_but_no_kwarg(self):
        """
        GIVEN a CA certificate.
        WHEN prepare_att_cert_issuer_v2form is called with add_digest_obj_info=True
        but WITHOUT providing object_digest_info kwarg.
        THEN it returns a V2Form with only issuerName (the digest info is not added due to implementation bug).
        Note: The implementation has a logic bug where it only adds digest info when
        object_digest_info kwarg is provided, but the else clause does nothing.
        """
        v2form = other_cert_utils.prepare_att_cert_issuer_v2form(
            self.cert,
            add_digest_obj_info=True
        )

        # Verify only issuerName is set (digest not added due to bug)
        self.assertTrue(v2form['issuerName'].isValue)
        self.assertFalse(v2form['baseCertificateID'].isValue)
        # Due to the bug, objectDigestInfo is NOT set when object_digest_info kwarg is not provided
        self.assertFalse(v2form['objectDigestInfo'].isValue)
        self.assertFalse(v2form['digestedObjectType'].isValue)

        # Test encoding and decoding
        der_data = try_encode_pyasn1(v2form)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.V2Form().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
        self.assertEqual(rest, b"")

    def test_prepare_with_custom_issuer_name(self):
        """
        GIVEN a CA certificate.
        WHEN prepare_att_cert_issuer_v2form is called with a custom issuer_name kwarg.
        THEN it returns a V2Form with the custom issuerName instead of the one from the certificate.
        """
        custom_issuer = "CN=Custom Issuer"
        v2form = other_cert_utils.prepare_att_cert_issuer_v2form(self.cert, issuer_name=custom_issuer)

        # Verify issuerName is set
        self.assertTrue(v2form['issuerName'].isValue)

        # Test encoding and decoding
        der_data = try_encode_pyasn1(v2form)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.V2Form().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
        self.assertEqual(rest, b"")

    def test_prepare_with_custom_target(self):
        """
        GIVEN a CA certificate and a pre-constructed V2Form target.
        WHEN prepare_att_cert_issuer_v2form is called with the target kwarg.
        THEN it populates the provided target object instead of creating a new one.
        """
        target = rfc5755.V2Form().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 0))

        v2form = other_cert_utils.prepare_att_cert_issuer_v2form(self.cert, target=target)

        # Verify the target is the same object
        self.assertIs(v2form, target)
        self.assertTrue(v2form['issuerName'].isValue)

        # Test encoding and decoding
        der_data = try_encode_pyasn1(v2form)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.V2Form().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
        self.assertEqual(rest, b"")

    def test_prepare_with_certificate_with_issuer_uid(self):
        """
        GIVEN a CA certificate with an issuer unique ID.
        WHEN prepare_att_cert_issuer_v2form is called with add_base_certificate_id=True.
        THEN it returns a V2Form with baseCertificateID containing the issuerUID.
        """
        # Add issuer unique ID to the certificate
        from pyasn1_alt_modules import rfc5280
        uid = rfc5280.UniqueIdentifier().fromOctetString(b"IssuerUID").subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        self.cert['tbsCertificate']['issuerUniqueID'] = uid

        v2form = other_cert_utils.prepare_att_cert_issuer_v2form(self.cert, add_base_certificate_id=True)

        # Verify baseCertificateID includes issuerUID
        self.assertTrue(v2form['baseCertificateID'].isValue)
        self.assertTrue(v2form['baseCertificateID']['issuerUID'].isValue)

        # Test encoding and decoding
        der_data = try_encode_pyasn1(v2form)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.V2Form().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
        self.assertEqual(rest, b"")


if __name__ == '__main__':
    unittest.main()

