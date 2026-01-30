# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from pyasn1.type import tag
from pyasn1_alt_modules import rfc5755

from resources import other_cert_utils
from resources.asn1utils import try_decode_pyasn1
from resources.other_cert_utils import prepare_issuer_serial_structure
from unit_tests.utils_for_test import try_encode_pyasn1


class TestPrepareIssuerSerialStructure(unittest.TestCase):
    def test_prepare_issuer_serial_structure_basic(self):
        """
        GIVEN an issuer name and a serial number.
        WHEN prepare_issuer_serial_structure is called.
        THEN the returned IssuerSerial object contains the correct issuer and serial number.
        """
        issuer = "CN=Test Issuer"
        serial_number = 12345
        
        result = other_cert_utils.prepare_issuer_serial_structure(issuer, serial_number)

        self.assertIsInstance(result, rfc5755.IssuerSerial)
        self.assertEqual(serial_number, int(result['serial']))
        self.assertTrue(result['issuer'].hasValue())

    def test_prepare_issuer_serial_structure_with_uid(self):
        """
        GIVEN an issuer name, a serial number, and an issuer unique ID.
        WHEN prepare_issuer_serial_structure is called.
        THEN the returned IssuerSerial object contains the correct issuer, serial number, and issuerUID.
        """
        issuer = "CN=Test Issuer"
        serial_number = 12345
        issuer_uid = b'\x01\x02\x03'
        
        result = prepare_issuer_serial_structure(issuer, serial_number, issuer_uid=issuer_uid)
        self.assertEqual(issuer_uid, result['issuerUID'].asOctets())

    def test_prepare_issuer_serial_structure_target(self):
        """
        GIVEN an issuer name, a serial number, and an existing target IssuerSerial object with
        implicit tagging.
        WHEN prepare_issuer_serial_structure is called with the target.
        THEN the returned object is the target object populated with the correct issuer and serial number.
        """
        target = rfc5755.IssuerSerial().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 1))
        issuer = "CN=Test Issuer"
        serial_number = 12345
        result = prepare_issuer_serial_structure(issuer, serial_number, target=target)
        self.assertEqual(serial_number, int(result['serial']))

        der_data = try_encode_pyasn1(result)
        obj, rest = try_decode_pyasn1(der_data, asn1_spec=rfc5755.IssuerSerial().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 1)))
        self.assertEqual(rest, b"")

if __name__ == '__main__':
    unittest.main()
