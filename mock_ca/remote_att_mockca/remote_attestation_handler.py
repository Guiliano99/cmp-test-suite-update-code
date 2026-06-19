# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Env-wired RemoteAttestationHandler for the demonstration environment.

Subclass of :class:`mock_ca.remote_attestation_handler.RemoteAttestationHandler`
that builds a :class:`libattest.ra.RemoteAttestationEngine` from environment
variables on construction (a :class:`~libattest.ra.ProfileRegistry` over a
:class:`mock_ca.verifier_registry.VerifierRegistry`, plus a
:class:`~libattest.ra.NonceStore`) and hands it to the base class.  All nonce
issuance / verification logic lives in the engine.

Environment variables consumed
------------------------------
``VERIFIER_OID_ROUTES``    JSON map ``{ "<oid-dot>": "<url>", ... }`` — evidence-
                           type OID → verifier URL.
``VERIFIER_URL_FALLBACK``  Default URL when the OID has no registered route.
``TPM_QUOTE_PCRS``         PCR set the quote profile broadcasts in respInfo.
``TPM_PCR_SELECTION_OID``  Quote-leg request-type OID.
``TPM_KEY_ATTEST_OID``     Certify-leg request-type OID.
``EAR_OID``                EAR-extension OID (raw JWT, or id-pe-cmw for CMW).

At least one of ``VERIFIER_OID_ROUTES`` / ``VERIFIER_URL_FALLBACK`` must produce
a usable route or :meth:`VerifierRegistry.from_environment` raises at startup so
the operator sees a deployment error before the first GenM arrives.
"""

from __future__ import annotations

import logging
from typing import Optional

from libattest.ra import NonceStore, RemoteAttestationEngine
from mock_ca.attestation_routes import build_profile_registry_from_environment
from mock_ca.db_config_vars import RemoteAttestationConfig
from mock_ca.remote_attestation_handler import RemoteAttestationHandler as _BaseHandler
from mock_ca.verifier_registry import VerifierRegistry


class RemoteAttestationHandler(_BaseHandler):
    """RemoteAttestationHandler wired up for the demo's verifier(s).

    Builds a :class:`VerifierRegistry` from env vars, a
    :class:`~libattest.ra.ProfileRegistry` over it, and a single
    :class:`~libattest.ra.RemoteAttestationEngine` (one shared
    :class:`~libattest.ra.NonceStore`), then hands the engine to the base class.
    """

    def __init__(
        self,
        config: Optional[RemoteAttestationConfig] = None,
        engine: Optional[RemoteAttestationEngine] = None,
    ) -> None:
        """Build the env-wired engine (unless one is injected) and wire the base."""
        if engine is None:
            registry = VerifierRegistry.from_environment()
            profiles = build_profile_registry_from_environment(
                verifier_registry=registry
            )
            engine = RemoteAttestationEngine(
                profiles=profiles, nonce_store=NonceStore()
            )
            self._verifier_registry: Optional[VerifierRegistry] = registry
            logging.info(
                "Veraison RemoteAttestationHandler ready: registry=%s profiles=%s",
                registry.snapshot(),
                profiles.snapshot(),
            )
        else:
            self._verifier_registry = None
        super().__init__(config=config, engine=engine)

    # ── Convenience accessors used by tests / external embedders ─────────────

    @property
    def verifier_registry(self) -> Optional[VerifierRegistry]:
        """The underlying :class:`VerifierRegistry` (or ``None`` if injected).

        Kept for tests/embedders that registered extra verifiers via
        :meth:`VerifierRegistry.register_oid_route` after construction.  Note:
        with the engine model the profile registry is built once from this
        registry at startup, so post-hoc route changes need a profile rebuild.
        """
        return self._verifier_registry
