# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from mock_ca.ca_handler import CAHandler


class TestCAHandlerUseOpenSSL(unittest.TestCase):
    def test_use_openssl_reaches_the_protection_handler(self):
        """
        GIVEN the `use_openssl` argument of the `CAHandler`.
        WHEN the `CAHandler` is created with `use_openssl=False`, and with the default.
        THEN its `ProtectionHandler` skips OpenSSL for `False` and uses it by default.
        """
        self.assertFalse(CAHandler(use_openssl=False).protection_handler.prot_handler_config.use_openssl)
        self.assertTrue(CAHandler().protection_handler.prot_handler_config.use_openssl)


if __name__ == "__main__":
    unittest.main()
