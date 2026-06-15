# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""RA-side nonce generation, storage, and verifier-routing.

Under ``constraint.md`` §9 (revised), the MockCA owns nonce state:

* Nonces are generated locally with :func:`os.urandom`, never fetched from
  the verifier.
* Nonces are stored under ``(tx_id, evidence_oid_der, instance)`` along
  with the resolved verifier URL, so Phase-3 dispatch is a single lookup.
* Each nonce is consumed exactly once (the second match raises
  :class:`ReplayError`) and per-tx state is dropped on transaction
  completion or TTL expiry.

Routing precedence at issue time (the attestation-freshness draft defines
no ``hint`` field; routing derives from the request type):

1. **OID** — when the evidence OID is set AND maps to a known route
   in the :class:`~mock_ca.verifier_registry.VerifierRegistry`.
2. **Fallback** — the registry's configured ``VERIFIER_URL_FALLBACK``.
3. Otherwise, :class:`SystemFailure` is raised so the CMP layer can return
   ``PKIFailureInfo: systemFailure`` to the client.

The handler is the *only* place in the MockCA that knows where evidence
goes; everything else looks up the URL via the :class:`NonceState`
returned from :meth:`consume`.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

from libattest.formats.tpm import (
    make_pcr_selection_resp_info,
    resolve_tpm_pcr_selection_oid,
)

from mock_ca.verifier_registry import VerifierRegistry

# OID of the TcgAttestQuote evidence statement (TCG TPM2 attestation, §DR-9).
ID_TCG_ATTEST_QUOTE: str = "2.23.133.20.2"


def _parse_pcr_list_env(value: str) -> list[int]:
    """Parse ``TPM_QUOTE_PCRS`` env value (e.g. ``"0,1,2,3,4"``).

    Empty entries are ignored.  Each entry must parse as a non-negative int;
    invalid entries are silently dropped with a log warning so a typo does
    not break startup.  Returns ``[0,1,2,3,4]`` if the env is empty or
    completely unparseable.
    """
    fallback = [0, 1, 2, 3, 4]
    if not value:
        return fallback
    out: list[int] = []
    for tok in value.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            n = int(tok)
        except ValueError:
            logger.warning(
                "TPM_QUOTE_PCRS: ignoring non-integer entry %r", tok
            )
            continue
        if n < 0:
            logger.warning(
                "TPM_QUOTE_PCRS: ignoring negative PCR index %d", n
            )
            continue
        out.append(n)
    return out or fallback

logger = logging.getLogger(__name__)


class ReplayError(Exception):
    """Raised when a (tx_id, oid, instance) slot is consumed a second time."""


class SystemFailure(Exception):
    """Raised when no verifier route can be resolved for a request.

    The MockCA's outer error handler maps this to CMP
    ``PKIFailureInfo: systemFailure`` so the client knows the rejection is
    on the CA side, not a bad request.
    """


# ── Data records ─────────────────────────────────────────────────────────────


@dataclass
class NonceState:
    """One RA-issued nonce with its lifecycle and routing metadata.

    ``verifier_url`` is resolved at issue time using the oid > fallback
    precedence and frozen on this record.  Phase-3 dispatch never
    re-resolves; it just submits to ``verifier_url``.

    The ``nonce`` field — the attestation nonce ``N`` used as
    ``TPM2_Quote.qualifyingData`` — is always plaintext on the wire.
    """

    nonce: bytes                 # plaintext attestation nonce N (always wire-side plaintext)
    tx_id: bytes                 # CMP transactionID — for diagnostics/logging
    evidence_oid_der: Optional[bytes]   # DER-encoded evidence-statement OID, or None
    evidence_oid_str: Optional[str]     # dot-form, for logging
    instance: int                # 0-based per-OID instance within tx_id
    verifier_url: str            # resolved at issuance via the registry
    created_at: float            # time.monotonic() at issuance
    expires_at: float            # created_at + ttl_seconds
    consumed: bool = False
    consumed_at: Optional[float] = None

    # NonceResponse.respInfo — DER of the type-specific response value.
    # For TcgAttestQuote slots this is DER(TpmAttestationParams): the PCR
    # list plus the negotiated hash algorithm the attester must quote.
    # None ↔ respInfo omitted on the wire.
    resp_info: Optional[bytes] = None


@dataclass
class _TxState:
    """All state belonging to a single CMP transaction.

    Lives in ``NonceHandler._tx`` keyed by ``tx_id``.
    """

    nonces: dict[tuple[Optional[bytes], int], NonceState] = field(default_factory=dict)
    # The (oid_der, instance) → NonceState map.  Note oid_der can be None
    # when the client omitted NonceRequest.type — those are addressed by
    # (None, 0), (None, 1), … in issue order.

    expires_at: float = 0.0


# ── Main handler ─────────────────────────────────────────────────────────────


class NonceHandler:
    """Per-transaction RA nonce generator + routing resolver.

    Not thread-aware in upstream cmp-test-suite usage (single-threaded
    request flow), but holds an internal ``Lock`` so future multi-worker
    deployments don't re-introduce a race.

    Construction takes a :class:`VerifierRegistry`; the handler does not
    talk to env vars itself, which keeps tests clean (build a Registry,
    pass it in, exercise the handler).
    """

    DEFAULT_TTL_SECONDS = 300
    DEFAULT_NONCE_BYTES = 32

    @property
    def tpm_pcr_selection_oid(self) -> str:
        """The configured PCR-selection / quote-parameter type OID."""
        return self._tpm_pcr_selection_oid

    @property
    def tcg_attest_quote_oid(self) -> str:
        """The TcgAttestQuote evidence-statement OID."""
        return ID_TCG_ATTEST_QUOTE

    def __init__(
        self,
        registry: VerifierRegistry,
        ttl_seconds: Optional[int] = None,
        nonce_bytes: Optional[int] = None,
        tpm_pcr_selection_oid: Optional[str] = None,
        tpm_quote_pcrs: Optional[list[int]] = None,
    ):
        self._registry = registry
        self._tx: dict[bytes, _TxState] = {}
        self._lock = Lock()
        self._ttl = int(ttl_seconds or os.environ.get("NONCE_TTL_SECONDS", self.DEFAULT_TTL_SECONDS))
        self._nonce_bytes = int(nonce_bytes or self.DEFAULT_NONCE_BYTES)
        # PCR-selection type OID and the PCR list the MockCA wants quoted,
        # both env-driven so docker-compose can change them without code
        # edits.  The hash algorithm is negotiated: the attester proposes a
        # TPM_ALG_ID in NonceRequest.reqInfo (TpmAttestationParams); the
        # MockCA echoes the proposal when supported, else counter-proposes
        # SHA-256 (0x000B), the only algorithm in _SUPPORTED_HASH_ALG_IDS today.
        self._tpm_pcr_selection_oid: str = (
            tpm_pcr_selection_oid if tpm_pcr_selection_oid is not None
            else resolve_tpm_pcr_selection_oid()
        )
        self._tpm_quote_pcrs: list[int] = (
            list(tpm_quote_pcrs) if tpm_quote_pcrs is not None
            else _parse_pcr_list_env(os.environ.get("TPM_QUOTE_PCRS", "0,1,2,3,4"))
        )

    # ── Issuance (Phase 1) ────────────────────────────────────────────────────

    def issue(
        self,
        tx_id: bytes,
        evidence_oid_dot: Optional[str],
        evidence_oid_der: Optional[bytes],
        proposed_hash_alg_id: Optional[int] = None,
    ) -> NonceState:
        """Generate a fresh nonce for a ``NonceRequest``.

        Resolves the verifier URL using oid > fallback precedence and stores
        the result on the returned :class:`NonceState` so the dispatcher
        does not need to re-resolve.

        Auto-increments the per-OID instance index for multi-TPM scenarios:
        two ``issue()`` calls with the same ``(tx_id, evidence_oid_der)``
        return ``instance=0`` and ``instance=1`` respectively.

        For TcgAttestQuote requests the returned state carries
        ``resp_info = DER(TpmAttestationParams)`` — the PCR list plus the
        negotiated hash algorithm (the attester's *proposed_hash_alg_id* is
        echoed when supported, else SHA-256 is counter-proposed).

        :raises SystemFailure: if no verifier route can be resolved.
        """
        with self._lock:
            self._evict_expired_locked()
            tx = self._tx.setdefault(tx_id, _TxState())

            if tx.expires_at == 0.0:
                tx.expires_at = time.monotonic() + self._ttl

            verifier_url = self._resolve_verifier_url(evidence_oid_dot)

            # Compute next instance index for this OID within this tx.
            existing_for_oid = [
                inst
                for (oid, inst) in tx.nonces.keys()
                if oid == evidence_oid_der
            ]
            instance = (max(existing_for_oid) + 1) if existing_for_oid else 0

            now = time.monotonic()
            plaintext_nonce = os.urandom(self._nonce_bytes)

            resp_info: Optional[bytes] = None

            # TcgAttestQuote — emit a TpmAttestationParams respInfo so the
            # attester quotes the verifier-selected PCRs using the negotiated
            # hash algorithm.
            if evidence_oid_dot == ID_TCG_ATTEST_QUOTE:
                resp_info = self._build_pcr_selection_resp_info(proposed_hash_alg_id)

            state = NonceState(
                nonce=plaintext_nonce,
                tx_id=tx_id,
                evidence_oid_der=evidence_oid_der,
                evidence_oid_str=evidence_oid_dot,
                instance=instance,
                verifier_url=verifier_url,
                created_at=now,
                expires_at=now + self._ttl,
                resp_info=resp_info,
            )
            tx.nonces[(evidence_oid_der, instance)] = state

            logger.info(
                "NonceHandler.issue tx=%s oid=%s inst=%d url=%s N=%dB%s",
                tx_id.hex(),
                evidence_oid_dot or "<none>",
                instance,
                verifier_url,
                len(state.nonce),
                f" respInfo={len(resp_info)}B" if resp_info else "",
            )
            return state

    # ── Consumption (Phase 3) ─────────────────────────────────────────────────

    def consume(
        self,
        tx_id: bytes,
        evidence_oid_der: Optional[bytes],
        instance: int,
    ) -> NonceState:
        """Return the nonce for ``(tx_id, oid, instance)`` and mark it consumed.

        Used by the IR-time dispatcher.  After the call, the same triple
        cannot be consumed again in the same transaction
        (:class:`ReplayError`).

        :raises KeyError:    no nonce was issued for that triple.
        :raises ValueError:  the nonce expired.
        :raises ReplayError: the nonce was already consumed in this tx.
        """
        with self._lock:
            self._evict_expired_locked()
            tx = self._tx.get(tx_id)
            if tx is None:
                raise KeyError(
                    f"no nonces issued for tx_id={tx_id.hex()} "
                    "(transaction unknown or already cleaned up)"
                )
            state = tx.nonces.get((evidence_oid_der, instance))
            if state is None:
                oid_repr = (
                    evidence_oid_der.hex() if evidence_oid_der is not None else "<none>"
                )
                raise KeyError(
                    f"no nonce for (tx={tx_id.hex()}, oid={oid_repr}, "
                    f"instance={instance})"
                )
            now = time.monotonic()
            if now > state.expires_at:
                del tx.nonces[(evidence_oid_der, instance)]
                raise ValueError(
                    f"nonce expired (TTL={self._ttl}s) for tx={tx_id.hex()}"
                )
            if state.consumed:
                raise ReplayError(
                    f"nonce already consumed at t={state.consumed_at} "
                    f"for tx={tx_id.hex()}"
                )
            state.consumed = True
            state.consumed_at = now
            logger.info(
                "NonceHandler.consume tx=%s oid=%s inst=%d url=%s",
                tx_id.hex(),
                state.evidence_oid_str or "<none>",
                instance,
                state.verifier_url,
            )
            return state

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def drop_transaction(self, tx_id: bytes) -> None:
        """Forget every nonce associated with a transaction.

        Called when an IR completes (success or fail) so the per-tx state
        is freed eagerly; otherwise it would only be cleaned up by the
        TTL sweep.
        """
        with self._lock:
            self._tx.pop(tx_id, None)

    def stats(self) -> dict:
        """Diagnostic snapshot — counts only, no nonce material."""
        with self._lock:
            return {
                "transactions": len(self._tx),
                "total_nonces": sum(len(t.nonces) for t in self._tx.values()),
                "consumed_nonces": sum(
                    1 for t in self._tx.values() for n in t.nonces.values() if n.consumed
                ),
            }

    # ── Internals ─────────────────────────────────────────────────────────────

    def _resolve_verifier_url(
        self,
        oid_dot: Optional[str],
    ) -> str:
        """oid > fallback resolution, in that order.

        Caller holds ``self._lock``.  Each branch logs the choice so a log
        trace makes the routing decision auditable.  The freshness draft
        defines no ``hint`` field; routing derives from the evidence OID.
        """
        # 1. OID — primary, when registered.
        oid_url = self._registry.resolve_oid(oid_dot)
        if oid_url:
            logger.debug("NonceHandler resolve: using OID %s → %s", oid_dot, oid_url)
            return oid_url

        # 2. Fallback URL.
        fallback = self._registry.fallback_url
        if fallback:
            logger.debug("NonceHandler resolve: using fallback %s", fallback)
            return fallback

        # 3. Out of options — refuse.
        raise SystemFailure(
            f"no verifier route resolvable (oid={oid_dot or '<none>'}); "
            "configure VERIFIER_OID_ROUTES or VERIFIER_URL_FALLBACK"
        )

    _SUPPORTED_HASH_ALG_IDS: frozenset[int] = frozenset({0x000B})

    def _build_pcr_selection_resp_info(
        self, proposed_hash_alg_id: Optional[int] = None
    ) -> bytes:
        """Build the ``respInfo`` DER carrying a ``TpmAttestationParams``.

        Accepts the attester's proposed ``hashAlgId`` when it is supported;
        otherwise uses the SHA-256 default (``0x000B``).  The PCR list is
        always filled from the configured ``_tpm_quote_pcrs``.
        """
        hash_alg_id = (
            proposed_hash_alg_id
            if proposed_hash_alg_id in self._SUPPORTED_HASH_ALG_IDS
            else 0x000B
        )
        resp_info = bytes(make_pcr_selection_resp_info(self._tpm_quote_pcrs, hash_alg_id))
        logger.info(
            "NonceHandler: attaching TpmAttestationParams respInfo: "
            "pcrs=%s hashAlgId=0x%04X (type oid=%s)",
            self._tpm_quote_pcrs,
            hash_alg_id,
            self._tpm_pcr_selection_oid,
        )
        return resp_info

    def _evict_expired_locked(self) -> None:
        """Drop transactions whose TTL window has elapsed."""
        now = time.monotonic()
        expired = [
            tid for tid, tx in self._tx.items()
            if tx.expires_at and now > tx.expires_at
        ]
        for tid in expired:
            count = len(self._tx[tid].nonces)
            del self._tx[tid]
            logger.info(
                "NonceHandler evicted expired transaction tx=%s (%d nonce(s))",
                tid.hex(), count,
            )
