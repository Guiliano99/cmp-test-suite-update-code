# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import unittest

from pyasn1_alt_modules import rfc4211, rfc4212

from resources import other_cert_utils
from resources.asn1utils import try_decode_pyasn1
from resources.ca_ra_utils import has_cert_template_a_value
from resources.certbuildutils import build_certificate
from unit_tests.utils_for_test import try_encode_pyasn1, compare_pyasn1_objects


class TestPrepareAltCertTemplateCertRequest(unittest.TestCase):
    """Test cases for the prepare_alt_cert_template_cert_request function."""

    def test_prepare_with_att_cert_template(self):
        """
        GIVEN an AttCertTemplate structure.
        WHEN prepare_alt_cert_template_cert_request is called with default parameters.
        THEN the returned CertRequest contains the correct certReqId, an empty CertTemplate,
        and a controls entry with the altCertTemplate.
        """
        holder = other_cert_utils.prepare_holder(entity_name="CN=Test Entity")
        att_cert_template = other_cert_utils.prepare_att_cert_template(
            version=1,
            holder=holder,
            serial_number=12345,
            not_before_time=datetime.datetime(2020, 1, 1),
        )

        cert_request = other_cert_utils.prepare_alt_cert_template_cert_request(
            other_cert_format=att_cert_template
        )

        self.assertEqual(int(cert_request["certReqId"]), 0)
        self.assertTrue(cert_request["controls"].isValue)
        self.assertEqual(len(cert_request["controls"]), 1)
        control = cert_request["controls"][0]
        self.assertEqual(control["type"], rfc4212.id_regCtrl_altCertTemplate)

        # Verify encoding and decoding
        der_data = try_encode_pyasn1(cert_request)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc4211.CertRequest())
        self.assertEqual(rest, b"")
        self.assertFalse(has_cert_template_a_value(decoded_obj["certTemplate"]))


    def test_prepare_with_attr_cert_template_correct_decoding(self):


        holder = other_cert_utils.prepare_holder(entity_name="CN=Test Entity")
        att_cert_template = other_cert_utils.prepare_att_cert_template(
            version=1,
            holder=holder,
            serial_number=12345,
            not_before_time=datetime.datetime(2020, 1, 1),
        )

        cert_request = other_cert_utils.prepare_alt_cert_template_cert_request(
            other_cert_format=att_cert_template
        )

        control = cert_request["controls"][0]
        self.assertEqual(control["type"], rfc4212.id_regCtrl_altCertTemplate)
        data, rest = try_decode_pyasn1(control["value"].asOctets(), rfc4212.AltCertTemplate())
        self.assertEqual(rest, b"")

        decoded_attr_cert_template, rest = try_decode_pyasn1(
            data["value"].asOctets(),
            rfc4212.AttCertTemplate()
        )
        self.assertEqual(rest, b"")
        self.assertEqual(1, int(decoded_attr_cert_template["version"]))
        self.assertTrue(compare_pyasn1_objects(holder, decoded_attr_cert_template["holder"]))
        self.assertEqual(12345, int(decoded_attr_cert_template["serialNumber"]))

    def test_prepare_with_openpgp_cert_template(self):
        """
        GIVEN an OpenPGPCertTemplateExtended structure.
        WHEN prepare_alt_cert_template_cert_request is called.
        THEN the returned CertRequest contains the correct structure with OpenPGP template.
        """
        native_template = b"dummy_openpgp_template_data"
        openpgp_template = other_cert_utils.prepare_openpgp_cert_template_extended(
            native_template=native_template
        )

        cert_request = other_cert_utils.prepare_alt_cert_template_cert_request(
            other_cert_format=openpgp_template,
            cert_req_id=5
        )

        self.assertEqual(int(cert_request["certReqId"]), 5)
        self.assertTrue(cert_request["controls"].isValue)
        self.assertEqual(len(cert_request["controls"]), 1)
        control = cert_request["controls"][0]
        self.assertEqual(control["type"], rfc4212.id_regCtrl_altCertTemplate)

        # Verify encoding and decoding
        der_data = try_encode_pyasn1(cert_request)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc4211.CertRequest())
        self.assertEqual(rest, b"")

    def test_prepare_with_custom_cert_req_id_string(self):
        """
        GIVEN an AttCertTemplate and a cert_req_id as string.
        WHEN prepare_alt_cert_template_cert_request is called with cert_req_id as string.
        THEN the returned CertRequest contains the correct integer certReqId.
        """
        att_cert_template = other_cert_utils.prepare_att_cert_template(version=1)

        cert_request = other_cert_utils.prepare_alt_cert_template_cert_request(
            other_cert_format=att_cert_template,
            cert_req_id="42"
        )

        self.assertEqual(int(cert_request["certReqId"]), 42)

    def test_prepare_with_custom_cert_req_id_int(self):
        """
        GIVEN an AttCertTemplate and a cert_req_id as integer.
        WHEN prepare_alt_cert_template_cert_request is called with cert_req_id as integer.
        THEN the returned CertRequest contains the correct certReqId.
        """
        att_cert_template = other_cert_utils.prepare_att_cert_template(version=1)

        cert_request = other_cert_utils.prepare_alt_cert_template_cert_request(
            other_cert_format=att_cert_template,
            cert_req_id=999
        )

        self.assertEqual(int(cert_request["certReqId"]), 999)

    def test_prepare_with_bad_controls_data(self):
        """
        GIVEN an AttCertTemplate and bad_controls_data=True.
        WHEN prepare_alt_cert_template_cert_request is called.
        THEN the returned CertRequest contains corrupted controls data.
        """
        att_cert_template = other_cert_utils.prepare_att_cert_template(version=1)

        cert_request = other_cert_utils.prepare_alt_cert_template_cert_request(
            other_cert_format=att_cert_template,
            bad_controls_data=True
        )

        self.assertTrue(cert_request["controls"].isValue)
        self.assertEqual(len(cert_request["controls"]), 1)
        control = cert_request["controls"][0]
        self.assertEqual(control["type"], rfc4212.id_regCtrl_altCertTemplate)

        data, rest = try_decode_pyasn1(control["value"], rfc4212.AltCertTemplate())
        self.assertNotEqual(rest, b"")

        control_value_bytes = bytes(control["value"])
        self.assertGreater(len(control_value_bytes), 0)

    def test_prepare_with_complex_att_cert_template(self):
        """
        GIVEN a complex AttCertTemplate with holder, issuer, serial number, and validity.
        WHEN prepare_alt_cert_template_cert_request is called.
        THEN the returned CertRequest properly encapsulates the complex template.
        """
        cert, _ = build_certificate()
        holder = other_cert_utils.prepare_holder(
            base_certificate_id=cert,
            entity_name="CN=Complex Entity"
        )

        att_cert_template = other_cert_utils.prepare_att_cert_template(
            version=1,
            holder=holder,
            serial_number=98765,
            not_before_time="20250101120000Z",
            not_after_time="20260101120000Z"
        )

        cert_request = other_cert_utils.prepare_alt_cert_template_cert_request(
            other_cert_format=att_cert_template,
            cert_req_id=100
        )

        self.assertEqual(int(cert_request["certReqId"]), 100)
        self.assertTrue(cert_request["controls"].isValue)

        # Verify encoding and decoding
        der_data = try_encode_pyasn1(cert_request)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc4211.CertRequest())
        self.assertEqual(rest, b"")

    def test_prepare_cert_template_is_empty(self):
        """
        GIVEN an AttCertTemplate.
        WHEN prepare_alt_cert_template_cert_request is called.
        THEN the certTemplate field in the returned CertRequest is empty (no fields set).
        """
        holder = other_cert_utils.prepare_holder(entity_name="CN=Test Entity")
        att_cert_template = other_cert_utils.prepare_att_cert_template(
            version=1,
            holder=holder,
            serial_number=123
        )

        cert_request = other_cert_utils.prepare_alt_cert_template_cert_request(
            other_cert_format=att_cert_template
        )

        cert_template = cert_request["certTemplate"]
        self.assertFalse(cert_template["version"].isValue)
        self.assertFalse(cert_template["subject"].isValue)
        self.assertFalse(cert_template["issuer"].isValue)
        self.assertFalse(cert_template["publicKey"].isValue)

    def test_invalid_other_cert_format_type_raises_error(self):
        """
        GIVEN an invalid object that is neither AttCertTemplate nor OpenPGPCertTemplateExtended.
        WHEN prepare_alt_cert_template_cert_request is called.
        THEN a TypeError should be raised.
        """
        invalid_template = rfc4211.CertTemplate()  # Wrong type

        with self.assertRaises(TypeError) as context:
            other_cert_utils.prepare_alt_cert_template_cert_request(
                other_cert_format=invalid_template  # type: ignore
            )

        self.assertIn("Invalid other_format type", str(context.exception))


if __name__ == "__main__":
    unittest.main()
