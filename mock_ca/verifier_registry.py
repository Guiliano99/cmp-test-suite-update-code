# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Verifier registry for the MockCA's RA-issued-nonce flow.

The registry holds the routing information consumed by
:class:`mock_ca.nonce_handler.NonceHandler` at GenM time:

* **OID → URL** map.  A ``NonceRequest`` carries a ``type`` OID (the
  evidence-statement type); that OID selects which verifier appraises the
  evidence.  The freshness draft (PR #26) has no ``hint`` field, so routing
  is purely OID-based with an optional fallback.

Configuration is normally supplied at startup via env vars:

* ``VERIFIER_OID_ROUTES``    JSON map ``{ "<oid-dot-form>": "<url>", ... }``.
                             Empty / unset is allowed.
* ``VERIFIER_URL_FALLBACK``  Default URL used when the OID lookup did not
                             resolve.  Optional.

A ``RuntimeError`` is raised at construction if **neither** the routes nor the
fallback are configured — this surfaces a deployment mistake at startup rather
than at IR time as a ``SystemFailure``.

The registry also exposes a programmatic API
(``register_oid_route``, ``set_fallback``) so tests and embedders can build a
registry without going through env vars.
"""

from __future__ import annotations

import json
import logging
import os
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)


class VerifierRegistry:
    """Thread-safe registry of OID→URL routes for verifier dispatch.

    Construction:

    * ``VerifierRegistry.from_environment()`` reads the env vars listed
      in the module docstring and returns a fully configured registry.
    * ``VerifierRegistry()`` returns an empty registry; tests use this and
      then call the ``register_*`` / ``set_fallback`` methods to populate it.

    All mutators take a single internal :class:`threading.Lock` so the registry
    can be updated at runtime (e.g. via an admin-API endpoint that adds a new
    verifier) without racing concurrent ``NonceHandler.issue()`` calls.
    """

    # ── Construction ──────────────────────────────────────────────────────────

    def __init__(
        self,
        oid_routes: Optional[dict[str, str]] = None,
        fallback_url: Optional[str] = None,
    ):
        self._lock = Lock()
        self._oid_routes: dict[str, str] = dict(oid_routes or {})
        self._fallback_url: Optional[str] = (
            fallback_url.rstrip("/") if fallback_url else None
        )

    @classmethod
    def from_environment(cls) -> "VerifierRegistry":
        """Build a registry from the canonical env vars.

        Raises:
            RuntimeError: when none of the routing mechanisms are configured.
                         A registry with no routes and no fallback cannot
                         resolve a single request, so we fail at startup
                         rather than ship a broken CA.
        """
        oid_routes = cls._parse_oid_routes_env()
        fallback = (os.environ.get("VERIFIER_URL_FALLBACK") or "").strip() or None

        registry = cls(
            oid_routes=oid_routes,
            fallback_url=fallback,
        )

        if not (oid_routes or fallback):
            raise RuntimeError(
                "VerifierRegistry: refusing to start — no routing configured. "
                "Set at least one of VERIFIER_OID_ROUTES or VERIFIER_URL_FALLBACK."
            )
        logger.info(
            "VerifierRegistry initialised: %d OID route(s), fallback=%s",
            len(oid_routes), fallback or "<unset>",
        )
        return registry

    # ── Runtime registration ──────────────────────────────────────────────────

    def register_oid_route(self, oid_dot_form: str, url: str) -> None:
        """Map an evidence-type OID to the verifier URL that appraises it.

        ``oid_dot_form`` is the canonical dot-decimal form, e.g.
        ``"2.23.133.20.1"`` for ``id-tcg-attest-certify``.  ``url`` is the
        base URL of the verifier (without trailing slash); the
        ``/submitEvidenceCMP`` path is appended at submit time.

        Calling this with an already-registered OID overwrites the prior URL.
        """
        if not oid_dot_form or not url:
            raise ValueError("oid_dot_form and url are both required")
        normalized = self._normalize_url(url)
        with self._lock:
            self._oid_routes[oid_dot_form] = normalized
        logger.info("Registered OID route: %s → %s", oid_dot_form, normalized)

    def set_fallback(self, url: Optional[str]) -> None:
        """Set or clear the last-resort fallback URL.

        Pass ``None`` to clear; the registry then refuses requests that
        match no OID route.
        """
        normalized = self._normalize_url(url) if url else None
        with self._lock:
            self._fallback_url = normalized
        logger.info("Fallback URL: %s", normalized or "<unset>")

    def unregister_oid_route(self, oid_dot_form: str) -> None:
        """Remove an OID→URL mapping."""
        with self._lock:
            self._oid_routes.pop(oid_dot_form, None)

    # ── Lookups ───────────────────────────────────────────────────────────────

    def resolve_oid(self, oid_dot_form: Optional[str]) -> Optional[str]:
        """Return the verifier URL for a given evidence-type OID, or None.

        ``None`` input or an unmapped OID both return ``None`` — the caller
        decides whether to fall back to the fallback URL or fail.
        """
        if not oid_dot_form:
            return None
        with self._lock:
            return self._oid_routes.get(oid_dot_form)

    @property
    def fallback_url(self) -> Optional[str]:
        """The configured fallback URL, or ``None`` if unset."""
        with self._lock:
            return self._fallback_url

    def snapshot(self) -> dict:
        """Return a debugging snapshot of the registry's current state."""
        with self._lock:
            return {
                "oid_routes": dict(self._oid_routes),
                "fallback_url": self._fallback_url,
            }

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalise a URL for comparison: strip trailing slashes, lowercase host.

        A more thorough normaliser would parse the URL and canonicalise
        scheme, host, port and path — but for the demo's plain-HTTP intra-
        compose traffic, trimming trailing slashes is enough to avoid the
        common ``http://x:8444`` vs ``http://x:8444/`` mismatch.
        """
        return url.rstrip("/")

    @staticmethod
    def _parse_oid_routes_env() -> dict[str, str]:
        """Decode the ``VERIFIER_OID_ROUTES`` JSON env var, with a clear error."""
        raw = os.environ.get("VERIFIER_OID_ROUTES", "").strip()
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"VERIFIER_OID_ROUTES is not valid JSON: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise RuntimeError("VERIFIER_OID_ROUTES must decode to a JSON object")
        return {str(k): str(v) for k, v in data.items()}
