# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch

from resources import ca_ra_utils
from resources.asn1utils import get_set_bitstring_names, is_bit_set
from resources.ca_ra_utils import build_rp_from_rr
from resources.certutils import parse_certificate
from resources.cmputils import build_cmp_revoke_request
from resources.exceptions import BadMessageCheck, BadRequest
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file

# TODO: Add more tests


class TestBuildRpFromRr(unittest.TestCase):
    def setUp(self):
        self.cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        self.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        self.rr = build_cmp_revoke_request(
            cert=self.cert,
            reason="keyCompromise",
        )

    def test_build_rp_from_valid_rr(self):
        """
        GIVEN a valid revocation request.
        WHEN building a revocation response from the request.
        THEN the response should be accepted.
        """
        self.rr["extraCerts"].append(self.cert)

        protected_rr = protect_pkimessage(
            self.rr,
            private_key=self.rsa_key,
            protection="signature",
            cert=self.cert,
        )
        rp, data = build_rp_from_rr(
            request=protected_rr,
            certs=[self.cert],
        )

        self.assertEqual(len(rp["body"]["rp"]["status"]), 1)
        self.assertEqual(data[0]["reason"], "keyCompromise")
        self.assertEqual(str(rp["body"]["rp"]["status"][0]["status"]), "accepted")

    def test_build_rp_from_rr_without_extra_certs(self):
        """
        GIVEN a revocation request without extra certificates.
        WHEN building a revocation response from the request.
        THEN an exception should be raised.
        """
        rp, _ = build_rp_from_rr(
            request=self.rr,
            certs=[self.cert],
        )

        self.assertEqual(len(rp["body"]["rp"]["status"]), 1)
        self.assertEqual(str(rp["body"]["rp"]["status"][0]["status"]), "rejection")

        result = is_bit_set(
            rp["body"]["rp"]["status"][0]["failInfo"],
            "addInfoNotAvailable",
        )
        self.assertTrue(result)

    def test_build_rp_from_rr_with_unprotected_rr(self):
        """
        GIVEN an unprotected revocation request.
        WHEN building a revocation response from the request.
        THEN the response should be rejected.
        """
        self.rr["extraCerts"].append(self.cert)
        with self.assertRaises(BadMessageCheck):
            rp, _ = build_rp_from_rr(
                request=self.rr,
                certs=[self.cert],
            )

    def test_build_rp_from_rr_keeps_instance_failinfo(self):
        """
        GIVEN a revocation request whose entry check raises an error with its own failinfo.
        WHEN building a revocation response from the request.
        THEN the status of the entry is rejected with exactly that failinfo, not the default of the error class.
        """
        error = BadRequest("The certificate template is invalid.", failinfo="badCertTemplate")
        with patch.object(ca_ra_utils, "validate_rev_details", side_effect=error):
            rp, _ = build_rp_from_rr(request=self.rr, certs=[self.cert], verify=False)

        status_info = rp["body"]["rp"]["status"][0]
        self.assertEqual(str(status_info["status"]), "rejection")
        self.assertEqual(get_set_bitstring_names(status_info["failInfo"]), "badCertTemplate")
