# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import io
import unittest

from robot import running

from resources.oidutils import id_KemBasedMac

KEM_TESTS = "tests_pq_and_hybrid/kem_tests.robot"


class TestBuildIrRequestKemBasedMacProtected(unittest.TestCase):
    def test_keyword_builds_the_protected_ir(self):
        """
        GIVEN the keyword `Build IR Request KEMBasedMac Protected` of kem_tests.robot
        WHEN it is run with a transaction ID and a shared secret, without the suite setup and without a CA,
        THEN it returns an IR with that transaction ID and the protectionAlg id-KemBasedMac.
        """
        suite = running.TestSuiteBuilder().build(KEM_TESTS)
        suite.setup.config(name=None)  # The suite setup talks to the CA.
        suite.tests.clear()
        test = suite.tests.create("Build The IR")
        test.body.create_keyword(
            "Build IR Request KEMBasedMac Protected",
            args=["${{b'A' * 16}}", "${{b'S' * 32}}", "True"],
            assign=["${ir}"],
        )
        test.body.create_keyword(
            "Should Be Equal", args=["${ir['header']['transactionID'].asOctets()}", "${{b'A' * 16}}"]
        )
        test.body.create_keyword(
            "Should Be Equal As Strings",
            args=["${ir['header']['protectionAlg']['algorithm']}", str(id_KemBasedMac)],
        )

        result = suite.run(
            output=None,
            log=None,
            report=None,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
            variable=["ENVIRONMENT:mock_ca"],
        )

        run = result.suite.tests[0]
        self.assertEqual(run.status, "PASS", run.message)


if __name__ == "__main__":
    unittest.main()
