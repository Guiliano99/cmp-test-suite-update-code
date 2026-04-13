# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Veraison-specific attestation extensions for the CMP MockCA.

This package isolates all Veraison verifier integration from the base
mock_ca modules so that upstream changes to mock_ca core files can be
merged with minimal conflicts.

Public API:
    RemoteAttestationHandler – drop-in replacement for the base handler
                                that adds Veraison nonce fetching and
                                token verification.
    VeraisonVerifier          – concrete AttestationVerifier for the
                                Veraison challenge-response API.
"""

from mock_ca.remote_att_mockca.attestation_verifier import VeraisonVerifier
from mock_ca.remote_att_mockca.remote_attestation_handler import RemoteAttestationHandler

__all__ = [
    "RemoteAttestationHandler",
    "VeraisonVerifier",
]
