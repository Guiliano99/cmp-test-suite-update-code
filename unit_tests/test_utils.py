# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest import mock

from resources import utils


class TestUtils(unittest.TestCase):
    def test_nonces_must_be_unique(self):
        """
        GIVEN a list of nonces.
        WHEN checking if the nonces are unique,
        THEN the nonces must be unique.
        """
        nonces_unique = [b"1234", b"5678", b"12314"]
        utils.nonces_must_be_unique(nonces_unique)

        nonces_dupe = [b"1234", b"5678", b"12314", b"1234"]
        with self.assertRaises(ValueError):
            utils.nonces_must_be_unique(nonces_dupe)

    def test_nonces_must_be_diverse(self):
        """
        GIVEN a list of nonces, which are not diverse.
        WHEN checking if the nonces are diverse,
        THEN an error is raised.
        """
        nonces_similar = [b"\x00" * 16, b"\x01" + b"\x00" * 15]
        with self.assertRaises(ValueError):
            utils.nonces_must_be_diverse(nonces_similar)

        nonces_diverse = [b"\x00" * 16, b"\xff" * 16]
        utils.nonces_must_be_diverse(nonces_diverse)

    def test_modify_random_str_index_zero(self):
        """
        GIVEN the string "abc" and `index=0`.
        WHEN `modify_random_str` is called,
        THEN only the first character is changed.
        """
        with mock.patch.object(utils.random, "randint", return_value=2):
            result = utils.modify_random_str("abc", index=0)
        self.assertNotEqual(result[0], "a")
        self.assertEqual(result[1:], "bc")

    def test_modify_random_str_skips_case_only_change(self):
        """
        GIVEN the string "abc", `index=1` and a random choice that first offers "B", then "x".
        WHEN `modify_random_str` is called,
        THEN the case-only replacement "B" is skipped and "x" is used.
        """
        with mock.patch.object(utils.random, "choice", side_effect=["B", "x"]):
            result = utils.modify_random_str("abc", index=1)
        self.assertEqual(result, "axc")


if __name__ == "__main__":
    unittest.main()
