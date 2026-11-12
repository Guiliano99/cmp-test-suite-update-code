# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import prepare_cert_template, prepare_extensions, verify_ca_basic_constraints
from resources.exceptions import BadCertTemplate
from resources.keyutils import generate_key


class TestVerifyCaBasicConstraints(unittest.TestCase):

    def test_ca_false_with_path_len(self):
        """
        GIVEN a certificate template with BasicConstraints `cA` FALSE and `pathLenConstraint` 5.
        WHEN verify_ca_basic_constraints is called,
        THEN a BadCertTemplate is raised by the `cA` FALSE check.
        """
        template = prepare_cert_template(
            generate_key("ed25519"),
            subject="CN=Hans the Tester",
            extensions=prepare_extensions(is_ca=False, path_length=5),
        )
        with self.assertRaises(BadCertTemplate) as ctx:
            verify_ca_basic_constraints(template)
        self.assertIn("CA was set to False", ctx.exception.message)


if __name__ == "__main__":
    unittest.main()
