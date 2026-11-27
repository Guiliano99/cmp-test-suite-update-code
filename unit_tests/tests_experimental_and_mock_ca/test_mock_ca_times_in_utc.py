# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import time
import unittest

from mock_ca.mock_fun import CertRevStateDB
from resources.certbuildutils import build_certificate
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import utc_now


class TestMockCATimesInUTC(unittest.TestCase):
    """The Mock CA must write the current time in UTC, whatever the local time zone of the machine is."""

    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.ca_cert, _ = build_certificate(cls.ca_key, "CN=Test CA")

    def setUp(self):
        # UTC+9 as a POSIX TZ string, which needs no zone data: a local time written as UTC
        # lies nine hours in the future.
        self._old_tz = os.environ.get("TZ")
        os.environ["TZ"] = "JST-9"
        time.tzset()
        self.assertEqual(time.localtime().tm_gmtoff, 9 * 3600)

    def tearDown(self):
        if self._old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self._old_tz
        time.tzset()

    def test_crl_revocation_date_is_utc(self):
        """
        GIVEN a revoked certificate and a machine in the time zone UTC+9.
        WHEN the Mock CA builds the CRL,
        THEN the revocationDate is not later than the current time in UTC.
        """
        rev_db = CertRevStateDB.build(revoked_certs=[self.ca_cert])
        crl = rev_db.get_crl_response(sign_key=self.ca_key, ca_cert=self.ca_cert)
        revocation_date = list(crl)[0].revocation_date_utc
        self.assertLessEqual(revocation_date, utc_now())
        self.assertGreaterEqual(revocation_date, crl.last_update_utc)


if __name__ == "__main__":
    unittest.main()
