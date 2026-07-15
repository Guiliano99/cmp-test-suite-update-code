# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Env-wired RemoteAttestationHandler for the demonstration environment.

Subclass of :class:`mock_ca.remote_attestation_handler.RemoteAttestationHandler`
that builds a :class:`libattest.ra.RemoteAttestationEngine` from environment
variables via :meth:`~libattest.ra.RemoteAttestationEngine.from_env` and hands
it to the base class.  All nonce issuance / verification logic, including the
env-var wiring itself, lives in ``libattest.ra`` now.

See :mod:`libattest.ra.env` for the full list of environment variables
consumed (``VERIFIER_OID_ROUTES``, ``VERIFIER_URL_FALLBACK``,
``TPM_QUOTE_PCRS``, ``TPM_PCR_SELECTION_OID``, ``TPM_KEY_ATTEST_OID``,
``EAR_OID``).  At least one of ``VERIFIER_OID_ROUTES`` / ``VERIFIER_URL_FALLBACK``
must produce a usable route or construction raises at startup so the operator
sees a deployment error before the first GenM arrives.
"""

from __future__ import annotations

from typing import Optional

from libattest.ra import RemoteAttestationEngine

from mock_ca.db_config_vars import RemoteAttestationConfig
from mock_ca.remote_attestation_handler import RemoteAttestationHandler as _BaseHandler


class RemoteAttestationHandler(_BaseHandler):
    """RemoteAttestationHandler wired up for the demo's verifier(s)."""

    def __init__(
        self,
        config: Optional[RemoteAttestationConfig] = None,
        engine: Optional[RemoteAttestationEngine] = None,
    ) -> None:
        """Build the env-wired engine (unless one is injected) and wire the base."""
        super().__init__(config=config, engine=engine or RemoteAttestationEngine.from_env())
