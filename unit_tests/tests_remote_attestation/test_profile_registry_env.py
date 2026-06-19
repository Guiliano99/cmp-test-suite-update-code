# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""MockCA env → :class:`libattest.ra.ProfileRegistry` wiring.

The per-OID attestation *route/profile* logic now lives in ``libattest.ra``
(``AttestationProfile`` / ``ProfileRegistry`` + ``tpm_profile``/``jwt_profile``)
and is unit-tested there.  The MockCA only keeps the environment wiring, so this
test covers exactly that: ``build_profile_registry_from_environment`` seeds the
TPM quote + certify profiles and routes any *extra* ``VERIFIER_OID_ROUTES`` OID
as an opaque-JWT profile — i.e. adding a new verifier/OID is pure configuration,
no MockCA code edit.
"""

import unittest

from mock_ca.attestation_routes import (
    ID_TCG_ATTEST_CERTIFY,
    ID_TCG_ATTEST_QUOTE,
    build_profile_registry_from_environment,
)
from mock_ca.verifier_registry import VerifierRegistry


class BuildProfileRegistryFromEnvTest(unittest.TestCase):
    """The MockCA's env → libattest.ra ProfileRegistry wiring."""

    def _registry(self, oid_routes, fallback=None):
        vr = VerifierRegistry(oid_routes=oid_routes, fallback_url=fallback)
        return build_profile_registry_from_environment(verifier_registry=vr)

    def test_quote_and_certify_profiles_seeded(self):
        profiles = self._registry(
            {
                ID_TCG_ATTEST_QUOTE: "http://tpm-verifier:8444",
                ID_TCG_ATTEST_CERTIFY: "http://tpm-verifier:8444",
            }
        )
        quote = profiles.by_statement(ID_TCG_ATTEST_QUOTE)
        self.assertIsNotNone(quote)
        self.assertEqual(quote.statement_oid, ID_TCG_ATTEST_QUOTE)

        certify = profiles.by_statement(ID_TCG_ATTEST_CERTIFY)
        self.assertIsNotNone(certify)
        self.assertEqual(certify.statement_oid, ID_TCG_ATTEST_CERTIFY)

    def test_extra_oid_becomes_jwt_profile_pure_config(self):
        new_oid = "1.3.6.1.4.1.99999.7"
        profiles = self._registry(
            {
                ID_TCG_ATTEST_QUOTE: "http://tpm-verifier:8444",
                new_oid: "http://sw-verifier:9000",
            }
        )
        # A new OID present only in VERIFIER_OID_ROUTES is routed with no MockCA
        # code change — the extensibility guarantee, from the MockCA's side.
        profile = profiles.by_statement(new_oid)
        self.assertIsNotNone(profile)
        self.assertEqual(profile.verifier_url, "http://sw-verifier:9000")


if __name__ == "__main__":
    unittest.main()
