# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Veraison-aware RemoteAttestationHandler for the demonstration environment.

Subclass of the upstream :class:`mock_ca.remote_attestation_handler.RemoteAttestationHandler`
that wires up the new :class:`mock_ca.nonce_handler.NonceHandler` plus
:class:`mock_ca.verifier_registry.VerifierRegistry` from environment
variables on construction.

Environment variables consumed
------------------------------
``VERIFIER_OID_ROUTES``    JSON map ``{ "<oid-dot>": "<url>", ... }``.
                           Maps an evidence-type OID to the verifier that
                           appraises it.  Empty or unset means no
                           OID-based routing.

``VERIFIER_URL_FALLBACK``  Optional default URL used when the request's
                           evidence-type OID has no registered route.

At least one of these must produce a usable route or
``VerifierRegistry.from_environment`` raises at startup so the operator
sees a deployment error before the first GenM arrives.

The class keeps the ``RemoteAttestationHandler`` name so existing imports
(``mock_ca.general_msg_handler``, ``mock_ca.remote_att_mockca.__init__``,
…) continue to work.
"""

from __future__ import annotations

import logging
from typing import Optional

from mock_ca.db_config_vars import RemoteAttestationConfig
from mock_ca.nonce_handler import NonceHandler
from mock_ca.remote_attestation_handler import RemoteAttestationHandler as _BaseHandler
from mock_ca.verifier_registry import VerifierRegistry


class RemoteAttestationHandler(_BaseHandler):
    """RemoteAttestationHandler wired up for the demo's Veraison verifier(s).

    Builds a :class:`VerifierRegistry` from environment variables, then a
    :class:`NonceHandler` over that registry, then hands the NonceHandler
    to the upstream base class.  All actual nonce-issuance logic lives in
    the base class plus the NonceHandler.
    """

    def __init__(self, config: Optional[RemoteAttestationConfig] = None):
        registry = VerifierRegistry.from_environment()
        nonce_handler = NonceHandler(registry=registry)
        super().__init__(config=config, nonce_handler=nonce_handler)

        logging.info(
            "Veraison RemoteAttestationHandler ready: registry=%s",
            registry.snapshot(),
        )

    # ── Convenience accessors used by tests / external embedders ─────────────

    @property
    def verifier_registry(self) -> VerifierRegistry:
        """Return the underlying :class:`VerifierRegistry`.

        Tests use this to dynamically register additional verifiers via
        :meth:`VerifierRegistry.register_oid_route` after construction.
        """
        assert self.nonce_handler is not None
        return self.nonce_handler._registry  # noqa: SLF001 — intentional accessor
