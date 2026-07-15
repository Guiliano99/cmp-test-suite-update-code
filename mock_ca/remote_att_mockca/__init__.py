# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Env-wired attestation extensions for the CMP MockCA.

This package isolates the demo's environment wiring from the base mock_ca
modules so that upstream changes to mock_ca core files can be merged with
minimal conflicts.

Public API:
    RemoteAttestationHandler – drop-in replacement for the base handler
                                that builds its engine from environment
                                variables (see :meth:`libattest.ra.
                                RemoteAttestationEngine.from_env`).
"""

from mock_ca.remote_att_mockca.remote_attestation_handler import RemoteAttestationHandler

__all__ = [
    "RemoteAttestationHandler",
]
