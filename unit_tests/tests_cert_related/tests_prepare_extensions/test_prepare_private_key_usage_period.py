# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc5280

from resources.asn1utils import try_decode_pyasn1
from resources.certbuildutils import prepare_private_key_usage_period

from unit_tests.utils_for_test import utc_now


class TestPreparePrivateKeyUsagePeriod(unittest.TestCase):
    def test_prepare_private_key_usage_period(self):
        """
        GIVEN `notBefore` and `notAfter` values.
        WHEN the extension is prepared,
        THEN the extension is correctly encoded and decoded.
        """
        extn = prepare_private_key_usage_period(
            critical=True,
            not_before=utc_now(),
            not_after=utc_now(),
        )

        self.assertEqual(rfc5280.id_ce_privateKeyUsagePeriod, extn["extnID"])
        self.assertEqual(True, extn["critical"])
        dec, rest = try_decode_pyasn1(extn["extnValue"].asOctets(), rfc5280.PrivateKeyUsagePeriod())  # type: ignore
        dec: rfc5280.PrivateKeyUsagePeriod
        self.assertEqual(b"", rest)
        self.assertTrue(dec["notBefore"].isValue)
        self.assertTrue(dec["notAfter"].isValue)

    def test_prepare_private_key_usage_period_with_not_before(self):
        """
        GIVEN `notBefore` value.
        WHEN the extension is prepared,
        THEN the extension is correctly encoded and decoded.
        """
        extn = prepare_private_key_usage_period(
            critical=False,
            not_before=utc_now(),
        )

        self.assertEqual(rfc5280.id_ce_privateKeyUsagePeriod, extn["extnID"])
        self.assertEqual(False, extn["critical"])
        dec, rest = try_decode_pyasn1(extn["extnValue"].asOctets(), rfc5280.PrivateKeyUsagePeriod())  # type: ignore
        dec: rfc5280.PrivateKeyUsagePeriod
        self.assertEqual(b"", rest)
        self.assertTrue(dec["notBefore"].isValue)
        self.assertFalse(dec["notAfter"].isValue)

    def test_prepare_private_key_usage_period_with_not_after(self):
        """
        GIVEN `notAfter` value.
        WHEN the extension is prepared,
        THEN the extension is correctly encoded and decoded.
        """
        extn = prepare_private_key_usage_period(
            critical=False,
            not_after=utc_now(),
        )

        self.assertEqual(rfc5280.id_ce_privateKeyUsagePeriod, extn["extnID"])
        self.assertEqual(False, extn["critical"])
        dec, rest = try_decode_pyasn1(extn["extnValue"].asOctets(), rfc5280.PrivateKeyUsagePeriod())  # type: ignore
        dec: rfc5280.PrivateKeyUsagePeriod
        self.assertEqual(b"", rest)
        self.assertFalse(dec["notBefore"].isValue)
        self.assertTrue(dec["notAfter"].isValue)

    def test_empty_prepare_private_key_usage_period(self):
        """
        GIVEN no `notBefore` and `notAfter` values.
        WHEN the extension is prepared,
        THEN the extension is correctly encoded and decoded.
        """
        extn = prepare_private_key_usage_period(critical=True)

        self.assertEqual(rfc5280.id_ce_privateKeyUsagePeriod, extn["extnID"])
        self.assertEqual(True, extn["critical"])
        self.assertEqual("3000", extn["extnValue"].asOctets().hex())
