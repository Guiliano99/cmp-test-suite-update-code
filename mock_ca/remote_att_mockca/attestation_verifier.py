# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Veraison verifier HTTP client — RA-issued nonce model.

Under the new architecture (constraint.md §9 revised, §10 added) the MockCA
generates and stores nonces locally and submits each piece of evidence to
the verifier together with the expected nonce in a single POST call.  The
verifier no longer maintains sessions.

This module exposes :class:`VeraisonVerifier`, a thin per-base-URL HTTP
client that talks to **one** verifier instance via two endpoints:

* ``POST {base_url}/submitEvidenceCMP``
  Body (JSON)::

      {
          "nonce":    "<base64>",          // the RA-issued nonce
          "evidence": "<base64>",          // DER of AttestationStatement / Bundle
          "oid":      "2.23.133.20.1"        // OPTIONAL evidence-type OID
      }

  Response::

      { "ear": "<EAR JWT compact-serialised>" }

* ``GET  {base_url}/ear-verification-key``
  Returns the verifier's EAR-JWT signing public key as PEM, used by the
  client to validate every EAR JWT it receives.

The client caches the EAR public key per instance (one cache entry per
base URL) and verifies every incoming EAR JWT before returning it.

Multiple verifier instances are addressed by constructing one
:class:`VeraisonVerifier` per base URL.  The MockCA dispatcher (typically
:class:`mock_ca.rats_handler.RatsHandler`) holds a small URL → instance
cache so repeat traffic to the same verifier reuses one client.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Optional

import requests
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.ear import ear_is_affirming, verify_ear_jwt

logger = logging.getLogger(__name__)

# Submit path is configurable so an example can target a distinct, non-colliding
# verifier endpoint; it must match the verifier's VERIFIER_SUBMIT_PATH. The
# default keeps existing behaviour, and one example runs at a time, so a single
# shared verifier service serves whichever path the active example configures.
_SUBMIT_EVIDENCE_PATH = os.environ.get("VERIFIER_SUBMIT_PATH") or "/submitEvidenceCMP"
_EAR_VERIFICATION_KEY_PATH = "/ear-verification-key"

# Opt-in: log the exact JSON body POSTed to the verifier (VERIFIER_LOG_PAYLOAD=1)
# so a user wiring their own verifier can see precisely what is sent.
_LOG_PAYLOAD = (os.environ.get("VERIFIER_LOG_PAYLOAD") or "").strip().lower() in (
    "1", "true", "yes",
)


class VeraisonVerifier:
    """HTTP client for a single Veraison verifier endpoint.

    The class is per-base-URL: one instance maps to one verifier service.
    Construction is cheap; in mock-ca's dispatcher we keep a URL → instance
    cache so repeat submissions during the same enrollment reuse one client
    (and therefore one cached EAR public key).

    :param base_url:
        Base URL of the Veraison verifier (no trailing slash; the client
        appends the canonical path per call).  Example:
        ``http://tpm-verifier:8444``.
    :param tls_verify:
        Whether to verify HTTPS certificates.  Defaults to ``False`` to
        match the demo's plain-HTTP intra-compose traffic.  Set ``True``
        (or a CA-bundle path) when running against an HTTPS verifier.
    :param fetch_timeout:
        Per-request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        tls_verify: bool = False,
        fetch_timeout: int = 10,
    ):
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = base_url.rstrip("/")
        self.tls_verify = tls_verify
        self.fetch_timeout = fetch_timeout
        # Lazy-fetched EC public key for EAR JWT signature verification.
        self._ear_public_key: Optional[ec.EllipticCurvePublicKey] = None
        logger.info("VeraisonVerifier initialised: base_url=%s", self.base_url)

    # ── /submitEvidenceCMP ────────────────────────────────────────────────────

    def submit_evidence(
        self,
        nonce: bytes,
        evidence: bytes,
        evidence_oid: Optional[str] = None,
        pcr_selection_der: Optional[bytes] = None,
    ) -> Optional[str]:
        """POST ``(nonce, evidence)`` to ``{base_url}/submitEvidenceCMP``.

        :param nonce:
            The nonce the MockCA bound to this evidence at GenM time
            (raw bytes; the client base64-encodes it on the wire).
        :param evidence:
            DER-encoded ``AttestationStatement`` payload — for TPM evidence
            this is a ``TcgAttestCertify`` or ``TcgAttestQuote`` SEQUENCE;
            for EAT, the JWT bytes.
        :param evidence_oid:
            Optional dot-form OID of the evidence type.  Forwarded to the
            verifier so its dispatcher can pick the right backend without
            re-parsing the bundle.
        :param pcr_selection_der:
            Optional DER bytes of the ``TpmAttestationParams`` the MockCA
            broadcast in ``NonceResponse.respInfo`` for this slot.
            Forwarded so the verifier can confirm the attester quoted the
            verifier-requested PCR set with the negotiated hash algorithm;
            only meaningful when *evidence_oid* is the TcgAttestQuote OID.

        :return:
            EAR JWT string on success; ``None`` if the verifier rejected
            the evidence (HTTP error, contraindicated verdict, or invalid
            EAR signature).
        """
        url = f"{self.base_url}{_SUBMIT_EVIDENCE_PATH}"
        body = {
            "nonce":    base64.b64encode(nonce).decode("ascii"),
            "evidence": base64.b64encode(evidence).decode("ascii"),
        }
        if evidence_oid:
            body["oid"] = evidence_oid
        if pcr_selection_der:
            body["pcr_selection"] = base64.b64encode(
                pcr_selection_der
            ).decode("ascii")

        logger.info(
            "VeraisonVerifier.submit_evidence: POST %s (oid=%s, evidence=%dB, "
            "nonce=%dB%s)",
            url, evidence_oid or "<none>", len(evidence), len(nonce),
            f", pcr_selection={len(pcr_selection_der)}B" if pcr_selection_der else "",
        )
        if _LOG_PAYLOAD:
            logger.info(
                "VeraisonVerifier.submit_evidence: JSON body to %s: %s",
                url, json.dumps(body),
            )

        try:
            resp = requests.post(
                url,
                json=body,
                timeout=self.fetch_timeout,
                verify=self.tls_verify,
                headers={"Accept": "application/json"},
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("VeraisonVerifier: HTTP error to %s: %s", url, exc)
            return None

        if not resp.ok:
            logger.warning(
                "VeraisonVerifier: %s returned %d: %s",
                url, resp.status_code, resp.text[:200],
            )
            return None

        try:
            data = resp.json()
        except ValueError as exc:
            logger.warning("VeraisonVerifier: non-JSON response from %s: %s", url, exc)
            return None

        ear_jwt = data.get("ear")
        if not ear_jwt:
            logger.warning(
                "VeraisonVerifier: response missing 'ear' field: %s",
                str(data)[:200],
            )
            return None

        # Verify the EAR JWT signature against the verifier's published key.
        pub_key = self._fetch_ear_public_key()
        if pub_key is not None:
            if not verify_ear_jwt(ear_jwt, pub_key):
                logger.warning(
                    "VeraisonVerifier: EAR JWT signature verification FAILED — rejecting"
                )
                return None
            logger.info("VeraisonVerifier: EAR JWT signature verified OK")
        else:
            logger.warning(
                "VeraisonVerifier: could not fetch EAR signing key from %s "
                "— skipping signature check (verdict still validated)",
                self.base_url,
            )

        if not ear_is_affirming(ear_jwt):
            logger.warning("VeraisonVerifier: EAR verdict is NOT affirming — rejecting")
            return None

        return ear_jwt

    # ── /ear-verification-key (cached) ────────────────────────────────────────

    def _fetch_ear_public_key(self) -> Optional[ec.EllipticCurvePublicKey]:
        """Lazily fetch and cache ``GET {base_url}/ear-verification-key``."""
        if self._ear_public_key is not None:
            return self._ear_public_key

        url = f"{self.base_url}{_EAR_VERIFICATION_KEY_PATH}"
        try:
            resp = requests.get(url, timeout=self.fetch_timeout, verify=self.tls_verify)
            resp.raise_for_status()
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            key = load_pem_public_key(resp.content)
            if not isinstance(key, ec.EllipticCurvePublicKey):
                logger.warning(
                    "VeraisonVerifier: EAR key from %s is not an EC key — skipping verification",
                    url,
                )
                return None
            self._ear_public_key = key
            return key
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "VeraisonVerifier: could not fetch EAR signing public key from %s: %s",
                url, exc,
            )
            return None
