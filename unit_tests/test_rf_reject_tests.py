# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import pathlib
import unittest

from robot import running

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SUITE_DIRS = ("tests", "tests_pq_and_hybrid", "tests_mock_ca")


class TestRFRejectTests(unittest.TestCase):
    def test_reject_tests_are_not_tagged_positive(self):
        """
        GIVEN the RF tests in tests/, tests_pq_and_hybrid/ and tests_mock_ca/
        WHEN the tests whose name contains ` Reject ` are collected,
        THEN there is at least one and none of them is tagged `positive`.
        """
        suite = running.TestSuiteBuilder().build(*(str(_ROOT / name) for name in _SUITE_DIRS))
        reject_tests = [test for test in suite.all_tests if " Reject " in test.name]
        self.assertTrue(reject_tests, "No RF test with ' Reject ' in its name was found.")
        tagged_positive = [
            f"{pathlib.Path(test.source).relative_to(_ROOT)}: {test.name}"
            for test in reject_tests
            if "positive" in test.tags
        ]
        self.assertEqual(tagged_positive, [])


if __name__ == "__main__":
    unittest.main()
