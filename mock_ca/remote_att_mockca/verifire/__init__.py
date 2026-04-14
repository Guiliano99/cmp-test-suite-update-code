# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""EAR/EAT verification utilities for the RATS demonstration environment.

This package provides :class:`EarEatVerifier`, a stateless helper that can:

* Extract and validate the ``eat_nonce`` claim from outgoing EAT tokens so the
  CA can confirm that the attester used the nonce it issued.
* Parse incoming EAR JWTs returned by Veraison and surface the per-submodule
  trust tier and trust vector without requiring a JWT library.
* Determine a consolidated (worst-case) trust tier across all submodules.

Public API::

    from mock_ca.remote_att_mockca.verifire import EarEatVerifier, EarResult, SubmodResult
    from mock_ca.remote_att_mockca.verifire import (
        TRUST_TIER_AFFIRMING,
        TRUST_TIER_WARNING,
        TRUST_TIER_CONTRAINDICATED,
        TRUST_TIER_NONE,
    )
"""

from mock_ca.remote_att_mockca.verifire.ear_eat_verifier import (
    TRUST_TIER_AFFIRMING,
    TRUST_TIER_CONTRAINDICATED,
    TRUST_TIER_NONE,
    TRUST_TIER_WARNING,
    EarEatVerifier,
    EarResult,
    SubmodResult,
)

__all__ = [
    "EarEatVerifier",
    "EarResult",
    "SubmodResult",
    "TRUST_TIER_AFFIRMING",
    "TRUST_TIER_WARNING",
    "TRUST_TIER_CONTRAINDICATED",
    "TRUST_TIER_NONE",
]
