# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.xwing import XWingPrivateKey


class TestXWINGKEM(unittest.TestCase):

    def test_encaps_and_decaps(self):
        """
        GIVEN two XWingPrivateKey instances.
        WHEN encaps and decaps are called.
        THEN the shared secret should be equal.
        """
        key = XWingPrivateKey.generate()
        ss_1, ct = key.public_key().encaps()
        ss_2 = key.decaps(ct)
        self.assertEqual(ss_1, ss_2)

