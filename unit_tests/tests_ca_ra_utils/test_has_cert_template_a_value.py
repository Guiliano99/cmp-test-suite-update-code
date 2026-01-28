# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import unittest

from pyasn1.type import tag
from pyasn1_alt_modules import rfc4211

from resources.ca_ra_utils import has_cert_template_a_value
from resources.certbuildutils import prepare_cert_template, prepare_validity
from resources.keyutils import load_private_key_from_file


class TestHasCertTemplateAValue(unittest.TestCase):
    """Test cases for the has_cert_template_a_value function."""

    @classmethod
    def setUpClass(cls) -> None:
        """Set up test fixtures that are reused across test methods."""
        cls.key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

    def test_empty_cert_template_returns_false(self):
        """
        GIVEN an empty certificate template with no fields set.
        WHEN has_cert_template_a_value is called.
        THEN it should return False.
        """
        cert_template = rfc4211.CertTemplate()
        # Just to demonstrate that the certificate template is not empty,
        # if created. Basically the reason for the existence of this function.
        self.assertTrue(cert_template.isValue)
        result = has_cert_template_a_value(cert_template)
        self.assertFalse(result)

    def test_cert_template_with_subject_returns_true(self):
        """
        GIVEN a certificate template with only the subject field set.
        WHEN has_cert_template_a_value is called.
        THEN it should return True.
        """
        cert_template = prepare_cert_template(
            key=self.key,
            subject="CN=Test Subject",
            include_fields="subject"
        )
        result = has_cert_template_a_value(cert_template)
        self.assertTrue(result)

    def test_cert_template_with_issuer_returns_true(self):
        """
        GIVEN a certificate template with only the issuer field set.
        WHEN has_cert_template_a_value is called.
        THEN it should return True.
        """
        cert_template = prepare_cert_template(
            key=self.key,
            issuer="CN=Test Issuer",
            include_fields="issuer"
        )
        result = has_cert_template_a_value(cert_template)
        self.assertTrue(result)

    def test_cert_template_with_serial_number_returns_true(self):
        """
        GIVEN a certificate template with only the serial number field set.
        WHEN has_cert_template_a_value is called.
        THEN it should return True.
        """
        cert_template = prepare_cert_template(
            key=self.key,
            serial_number=12345,
            include_fields="serialNumber"
        )
        result = has_cert_template_a_value(cert_template)
        self.assertTrue(result)

    def test_cert_template_with_public_key_returns_true(self):
        """
        GIVEN a certificate template with only the public key field set.
        WHEN has_cert_template_a_value is called.
        THEN it should return True.
        """
        cert_template = prepare_cert_template(
            key=self.key,
        )
        result = has_cert_template_a_value(cert_template)
        self.assertTrue(result)

    def test_cert_template_with_validity_not_before_returns_true(self):
        """
        GIVEN a certificate template with only validity.notBefore field set.
        WHEN has_cert_template_a_value is called.
        THEN it should return True.
        """
        validity = prepare_validity(
            not_before=datetime.datetime.now(),
            not_after=None
        )
        cert_template = prepare_cert_template(
            key=self.key,
            validity=validity,
            include_fields="validity, publicKey"
        )
        result = has_cert_template_a_value(cert_template)
        self.assertTrue(result)

    def test_cert_template_with_validity_not_after_returns_true(self):
        """
        GIVEN a certificate template with only validity.notAfter field set.
        WHEN has_cert_template_a_value is called.
        THEN it should return True.
        """
        validity = prepare_validity(
            not_before=None,
            not_after=datetime.datetime.now() + datetime.timedelta(days=365)
        )
        cert_template = prepare_cert_template(
            validity=validity,
            include_fields="validity"
        )
        result = has_cert_template_a_value(cert_template)
        self.assertTrue(result)

    def test_cert_template_with_validity_both_fields_returns_true(self):
        """
        GIVEN a certificate template with both validity.notBefore and validity.notAfter set.
        WHEN has_cert_template_a_value is called.
        THEN it should return True.
        """
        validity = prepare_validity(
            not_before=datetime.datetime.now(),
            not_after=datetime.datetime.now() + datetime.timedelta(days=365)
        )
        cert_template = prepare_cert_template(
            validity=validity,
            include_fields="validity"
        )
        result = has_cert_template_a_value(cert_template)
        self.assertTrue(result)

    def test_cert_template_with_validity_empty_returns_false(self):
        """
        GIVEN a certificate template with validity field present but no notBefore/notAfter set.
        WHEN has_cert_template_a_value is called.
        THEN it should return False.
        """
        cert_template = rfc4211.CertTemplate()
        cert_template["validity"] = rfc4211.OptionalValidity().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))
        result = has_cert_template_a_value(cert_template)
        self.assertFalse(result)

    def test_cert_template_with_multiple_fields_returns_true(self):
        """
        GIVEN a certificate template with multiple fields set (subject, issuer, serial number).
        WHEN has_cert_template_a_value is called.
        THEN it should return True.
        """
        cert_template = prepare_cert_template(
            key=self.key,
            subject="CN=Test Subject",
            issuer="CN=Test Issuer",
            serial_number=99999,
            include_fields="subject,issuer,serialNumber"
        )
        result = has_cert_template_a_value(cert_template)
        self.assertTrue(result)

    def test_cert_template_with_version_returns_true(self):
        """
        GIVEN a certificate template with only the version field set.
        WHEN has_cert_template_a_value is called.
        THEN it should return True.
        """
        cert_template = prepare_cert_template(
            version=2,
            include_fields="version"
        )
        result = has_cert_template_a_value(cert_template)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
