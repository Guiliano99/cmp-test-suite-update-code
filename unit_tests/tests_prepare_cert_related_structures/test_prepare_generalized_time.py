# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import time
import unittest

from resources.prepareutils import prepare_generalized_time


class TestPrepareGeneralizedTime(unittest.TestCase):
    """A POSIX timestamp is written as the UTC time it stands for, whatever the local time zone is."""

    def setUp(self):
        # UTC+9 as a POSIX TZ string, which needs no zone data.
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

    def test_timestamp_is_written_in_utc(self):
        """
        GIVEN the POSIX timestamp 0.0 and a machine in the time zone UTC+9.
        WHEN a GeneralizedTime is prepared from it,
        THEN it is 1970-01-01 00:00:00 in UTC.
        """
        self.assertEqual(str(prepare_generalized_time(0.0)), "19700101000000Z")


if __name__ == "__main__":
    unittest.main()
