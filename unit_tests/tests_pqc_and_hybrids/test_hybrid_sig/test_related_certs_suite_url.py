# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import io
import unittest

from robot import running

RELATED_CERTS_TESTS = "tests_pq_and_hybrid/rfc9783_related_certs.robot"


class TestRelatedCertsSuiteUrl(unittest.TestCase):
    def test_p10cr_is_posted_to_the_related_cert_endpoint(self):
        """
        GIVEN the suite setup of rfc9783_related_certs.robot with the mock_ca config, which appends the body type
        WHEN a test sends a p10cr with `Exchange PKIMessage` to `Get Related Cert URL`,
        THEN the request is posted to the related-cert endpoint itself, without the `/p10cr` suffix.
        """
        suite = running.TestSuiteBuilder().build(RELATED_CERTS_TESTS)
        suite.tests.clear()
        # A suite-file keyword wins over the RequestsLibrary keyword, so no request leaves the process.
        post = suite.resource.keywords.create(name="POST", args=["&{kwargs}"])
        post.body.create_keyword("Fail", args=["${kwargs}[url]"])
        test = suite.tests.create("Send A P10cr")
        test.body.create_keyword("Generate Default Key", assign=["${key}"])
        test.body.create_keyword("Build P10cr From Key", args=["${key}"], assign=["${p10cr}"])
        test.body.create_keyword("Get Related Cert URL", assign=["${ca_url}"])
        test.body.create_keyword("Exchange PKIMessage", args=["${p10cr}", "${ca_url}"])

        result = suite.run(
            output=None,
            log=None,
            report=None,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
            # A set ISSUED_KEY skips the initial IR of `Set Up Test Suite`, which talks to the CA.
            variable=["ENVIRONMENT:mock_ca", "ISSUED_KEY:issued"],
        )

        run = result.suite.tests[0]
        self.assertEqual(run.message, "http://127.0.0.1:5000/related-cert")


if __name__ == "__main__":
    unittest.main()
