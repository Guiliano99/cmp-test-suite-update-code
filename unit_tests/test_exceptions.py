# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import inspect
import unittest

from pyasn1_alt_modules import rfc9480

from resources import exceptions
from resources.exceptions import CMPTestSuiteError

# RFC 9810 Section 5.2.3: PKIFailureInfo name -> bit.
_BITS = dict(rfc9480.PKIFailureInfo.namedValues)


class TestExceptions(unittest.TestCase):
    def test_failinfo_and_bit_num_follow_rfc9810(self):
        """
        GIVEN every `CMPTestSuiteError` class that `resources.exceptions` exposes.
        WHEN its class-level `failinfo` and `bit_num` are compared with RFC 9810 `PKIFailureInfo`.
        THEN `failinfo` is a `PKIFailureInfo` name, and a class defined in `resources.exceptions` that declares
        `failinfo` or `bit_num` has the bit of that name.

        The bit of a class that inherits both from the keyutils_py base is not checked: BadConfig, UnknownOID and
        BodyRelevantError still have (systemFailure, 26) until keyutils_py fixes its base class, while RFC 9810
        gives systemFailure bit 25 (BUG-15). The client gets bit 25, because the response is built from the name.
        """
        classes = [o for o in vars(exceptions).values() if inspect.isclass(o) and issubclass(o, CMPTestSuiteError)]
        for cls in classes:
            with self.subTest(cls=cls.__name__):
                self.assertIn(cls.failinfo, _BITS)
                if cls.__module__ == exceptions.__name__ and vars(cls).keys() & {"failinfo", "bit_num"}:
                    self.assertEqual(cls.bit_num, _BITS[cls.failinfo])

    def test_str_error_details_is_one_entry(self):
        """
        GIVEN an error raised with a single string as `error_details`.
        WHEN its error details are read.
        THEN they hold the string as one entry, not one entry per character.
        """
        self.assertEqual(CMPTestSuiteError("message", error_details="abc").get_error_details(), ["abc"])


if __name__ == "__main__":
    unittest.main()
