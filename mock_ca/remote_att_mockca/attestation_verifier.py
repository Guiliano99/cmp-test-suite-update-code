# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Verifier HTTP client — thin re-export of :class:`libattest.ra.VeraisonVerifierClient`.

The ``/submitEvidenceCMP`` → EAR client (POST ``{nonce, evidence, oid?,
resp_info_json?}``; fetch + cache ``/ear-verification-key``; fail-closed EAR
signature + affirming-verdict check) moved into the protocol-agnostic
:mod:`libattest.ra` engine as :class:`~libattest.ra.VeraisonVerifierClient`.

The MockCA keeps the historical name :class:`VeraisonVerifier` as an alias so
existing imports (``mock_ca.remote_att_mockca.__init__``, tests) keep working.
The engine itself drives this client through each profile's
``verifier`` / ``verifier_url``; swapping in a different verifier is a
registration in ``libattest.ra`` — no MockCA change.
"""

from __future__ import annotations

from libattest.ra import VeraisonVerifierClient

# Backward-compatible alias for the historical MockCA class name.
VeraisonVerifier = VeraisonVerifierClient

__all__ = [
    "VeraisonVerifier",
    "VeraisonVerifierClient",
]
