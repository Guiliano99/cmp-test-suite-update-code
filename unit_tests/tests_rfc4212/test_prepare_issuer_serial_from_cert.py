# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.type import tag
from pyasn1_alt_modules import rfc9480, rfc5280, rfc5755
from resources import other_cert_utils
from resources.asn1utils import try_decode_pyasn1
from resources.prepareutils import prepare_name
from unit_tests.utils_for_test import try_encode_pyasn1


class TestPrepareIssuerSerialFromCert(unittest.TestCase):
    """Tests for preparing the IssuerSerial structure."""
    def test_prepare_from_cert(self):
        """
        GIVEN a certificate with serial number and issuer name.
        WHEN prepare_issuer_serial_from_cert is called.
        THEN the returned IssuerSerial object contains the correct issuer and serial number,
        and no issuerUID and is correctly encoded and decoded able.
        """

        issuer_ser_target = rfc5755.IssuerSerial()
        cert = rfc9480.CMPCertificate()
        tbs = cert['tbsCertificate']
        tbs['serialNumber'] = 12345
        tbs["issuer"] = prepare_name("CN=Test Issuer")
        issuer_ser = other_cert_utils.prepare_issuer_serial_from_cert(cert, target=issuer_ser_target)
        self.assertTrue(issuer_ser["issuer"].isValue)
        self.assertTrue(issuer_ser["serial"].isValue)
        self.assertFalse(issuer_ser["issuerUID"].isValue)

        der_data = try_encode_pyasn1(issuer_ser)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.IssuerSerial())
        self.assertEqual(rest, b"")


    def test_prepare_from_cert_with_uid(self):
        """
        GIVEN a certificate with serial number, issuer name, and issuer unique ID.
        WHEN prepare_issuer_serial_from_cert is called.
        THEN the returned IssuerSerial object contains the correct issuer,
        serial number, and issuerUID and is correctly encoded and decoded able.
        """
        issuer_ser_target = rfc5755.IssuerSerial()
        cert = rfc9480.CMPCertificate()
        uid = rfc5280.UniqueIdentifier().fromOctetString(b"Hello World!").subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        tbs = cert['tbsCertificate']
        tbs['serialNumber'] = 12345
        tbs["issuer"] = prepare_name("CN=Test Issuer")
        tbs['issuerUniqueID'] = uid
        issuer_ser = other_cert_utils.prepare_issuer_serial_from_cert(cert, target=issuer_ser_target)
        self.assertTrue(issuer_ser["issuer"].isValue)
        self.assertTrue(issuer_ser["serial"].isValue)
        self.assertTrue(issuer_ser["issuerUID"].isValue)

        der_data = try_encode_pyasn1(issuer_ser)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc5755.IssuerSerial())
        self.assertEqual(rest, b"")

if __name__ == '__main__':
    unittest.main()
