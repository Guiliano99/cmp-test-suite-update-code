# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc4211, rfc4212

from resources import other_cert_utils
from resources.asn1utils import try_decode_pyasn1
from resources.cmputils import prepare_controls_structure
from resources.certbuildutils import generate_certificate
from resources.keyutils import generate_key
from unit_tests.utils_for_test import try_encode_pyasn1


class TestPrepareOpenPGPCertTemplateExtended(unittest.TestCase):
    """Test cases for the prepare_openpgp_cert_template_extended function."""

    def test_prepare_with_native_template(self):
        """
        GIVEN a native OpenPGP certificate template in bytes.
        WHEN prepare_openpgp_cert_template_extended is called with native_template.
        THEN the returned OpenPGPCertTemplateExtended contains the nativeTemplate field set.
        """
        native_template = b"dummy_openpgp_template_data"

        result = other_cert_utils.prepare_openpgp_cert_template_extended(
            native_template=native_template
        )

        self.assertIsInstance(result, rfc4212.OpenPGPCertTemplateExtended)
        self.assertTrue(result["nativeTemplate"].isValue)
        self.assertEqual(bytes(result["nativeTemplate"]), native_template)
        self.assertFalse(result["controls"].isValue)

    def test_prepare_with_native_template_and_controls(self):
        """
        GIVEN a native template and controls structure.
        WHEN prepare_openpgp_cert_template_extended is called with both parameters.
        THEN the returned structure contains both nativeTemplate and controls.
        """
        native_template = b"openpgp_cert_template_bytes"
        key = generate_key()
        cert = generate_certificate(private_key=key)
        controls = prepare_controls_structure(cert=cert)

        result = other_cert_utils.prepare_openpgp_cert_template_extended(
            native_template=native_template,
            controls=controls
        )

        self.assertIsInstance(result, rfc4212.OpenPGPCertTemplateExtended)
        self.assertTrue(result["nativeTemplate"].isValue)
        self.assertEqual(bytes(result["nativeTemplate"]), native_template)
        self.assertTrue(result["controls"].isValue)
        self.assertEqual(len(result["controls"]), len(controls))

    def test_prepare_with_der_encoded_target(self):
        """
        GIVEN a DER-encoded OpenPGPCertTemplateExtended structure as bytes.
        WHEN prepare_openpgp_cert_template_extended is called with target as bytes.
        THEN the structure is decoded and returned correctly.
        """
        native_template = b"test_native_template"
        original = rfc4212.OpenPGPCertTemplateExtended()
        original["nativeTemplate"] = rfc4212.OpenPGPCertTemplate(native_template)

        der_encoded = try_encode_pyasn1(original)

        result = other_cert_utils.prepare_openpgp_cert_template_extended(
            target=der_encoded
        )

        self.assertIsInstance(result, rfc4212.OpenPGPCertTemplateExtended)
        self.assertTrue(result["nativeTemplate"].isValue)
        self.assertEqual(bytes(result["nativeTemplate"]), native_template)

    def test_prepare_with_existing_structure_target(self):
        """
        GIVEN an existing OpenPGPCertTemplateExtended structure.
        WHEN prepare_openpgp_cert_template_extended is called with target as the structure.
        THEN the same structure is returned unchanged.
        """
        native_template = b"existing_template"
        target = rfc4212.OpenPGPCertTemplateExtended()
        target["nativeTemplate"] = rfc4212.OpenPGPCertTemplate(native_template)

        result = other_cert_utils.prepare_openpgp_cert_template_extended(
            target=target
        )

        self.assertIs(result, target)
        self.assertTrue(result["nativeTemplate"].isValue)
        self.assertEqual(bytes(result["nativeTemplate"]), native_template)

    def test_prepare_with_target_and_controls(self):
        """
        GIVEN an existing OpenPGPCertTemplateExtended structure and controls.
        WHEN prepare_openpgp_cert_template_extended is called with both.
        THEN the controls are added to the existing structure.
        """
        native_template = b"template_with_controls"
        target = rfc4212.OpenPGPCertTemplateExtended()
        target["nativeTemplate"] = rfc4212.OpenPGPCertTemplate(native_template)

        key = generate_key()
        cert = generate_certificate(private_key=key)
        controls = prepare_controls_structure(cert=cert)

        result = other_cert_utils.prepare_openpgp_cert_template_extended(
            target=target,
            controls=controls
        )

        self.assertIsInstance(result, rfc4212.OpenPGPCertTemplateExtended)
        self.assertTrue(result["nativeTemplate"].isValue)
        self.assertTrue(result["controls"].isValue)
        self.assertEqual(len(result["controls"]), len(controls))

    def test_error_both_native_template_and_target(self):
        """
        GIVEN both native_template and target are specified with controls.
        WHEN prepare_openpgp_cert_template_extended is called.
        THEN a ValueError is raised.
        """
        native_template = b"template_bytes"
        target = rfc4212.OpenPGPCertTemplateExtended()
        target["nativeTemplate"] = rfc4212.OpenPGPCertTemplate(b"other_template")

        # Create controls to prevent early return
        key = generate_key()
        cert = generate_certificate(private_key=key)
        controls = prepare_controls_structure(cert=cert)

        with self.assertRaises(ValueError) as context:
            other_cert_utils.prepare_openpgp_cert_template_extended(
                native_template=native_template,
                target=target,
                controls=controls
            )

        self.assertIn("Cannot specify both", str(context.exception))

    def test_error_neither_native_template_nor_target(self):
        """
        GIVEN neither native_template nor target are specified.
        WHEN prepare_openpgp_cert_template_extended is called with no arguments.
        THEN a ValueError is raised.
        """
        with self.assertRaises(ValueError) as context:
            other_cert_utils.prepare_openpgp_cert_template_extended()

        self.assertIn("Either `native_template` or `target`", str(context.exception))

    def test_encode_and_decode_roundtrip(self):
        """
        GIVEN a prepared OpenPGPCertTemplateExtended structure.
        WHEN it is encoded to DER and decoded back.
        THEN the decoded structure matches the original.
        """
        native_template = b"roundtrip_test_template"
        original = other_cert_utils.prepare_openpgp_cert_template_extended(
            native_template=native_template
        )

        der_encoded = try_encode_pyasn1(original)
        decoded, rest = try_decode_pyasn1(der_encoded, rfc4212.OpenPGPCertTemplateExtended())

        self.assertEqual(rest, b"")
        self.assertIsInstance(decoded, rfc4212.OpenPGPCertTemplateExtended)
        self.assertTrue(decoded["nativeTemplate"].isValue)
        self.assertEqual(decoded["nativeTemplate"].asOctets(), native_template)

    def test_prepare_with_empty_native_template(self):
        """
        GIVEN an empty native template (empty bytes).
        WHEN prepare_openpgp_cert_template_extended is called.
        THEN the returned structure contains an empty nativeTemplate.
        """
        native_template = b""
        result = other_cert_utils.prepare_openpgp_cert_template_extended(
            native_template=native_template
        )

        self.assertIsInstance(result, rfc4212.OpenPGPCertTemplateExtended)
        self.assertTrue(result["nativeTemplate"].isValue)
        self.assertEqual(result["nativeTemplate"].asOctets(), native_template)

    def test_prepare_with_multiple_controls(self):
        """
        GIVEN a native template and multiple controls.
        WHEN prepare_openpgp_cert_template_extended is called.
        THEN all controls are included in the returned structure.
        """
        native_template = b"multi_control_template"

        # Create multiple controls
        key1 = generate_key()
        cert1 = generate_certificate(private_key=key1)
        controls1 = prepare_controls_structure(cert=cert1)

        key2 = generate_key()
        cert2 = generate_certificate(private_key=key2)
        controls2 = prepare_controls_structure(cert=cert2)

        # Combine controls
        combined_controls = rfc4211.Controls()
        combined_controls.extend(controls1)
        combined_controls.extend(controls2)

        result = other_cert_utils.prepare_openpgp_cert_template_extended(
            native_template=native_template,
            controls=combined_controls
        )

        self.assertIsInstance(result, rfc4212.OpenPGPCertTemplateExtended)
        self.assertTrue(result["controls"].isValue)
        self.assertEqual(len(result["controls"]), len(combined_controls))

    def test_prepare_der_target_with_trailing_data(self):
        """
        GIVEN a DER-encoded OpenPGPCertTemplateExtended with trailing data.
        WHEN prepare_openpgp_cert_template_extended is called with this bytes target.
        THEN the structure is decoded and a debug log is recorded about trailing data.
        """
        native_template = b"template_with_trailing"
        original = rfc4212.OpenPGPCertTemplateExtended()
        original["nativeTemplate"] = rfc4212.OpenPGPCertTemplate(native_template)

        der_encoded = try_encode_pyasn1(original)
        der_with_trailing = der_encoded + b"TRAILING_DATA"

        # This should still work and log a debug message
        with self.assertLogs(level='DEBUG') as log:
            result = other_cert_utils.prepare_openpgp_cert_template_extended(
                target=der_with_trailing
            )

        self.assertIsInstance(result, rfc4212.OpenPGPCertTemplateExtended)
        self.assertTrue(result["nativeTemplate"].isValue)
        self.assertTrue(any("trailing data" in message.lower() for message in log.output))


if __name__ == "__main__":
    unittest.main()
