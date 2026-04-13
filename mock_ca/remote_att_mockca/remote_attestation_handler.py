# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Veraison-aware RemoteAttestationHandler for the demonstration environment.

This module subclasses the base ``RemoteAttestationHandler`` to wire up a
``VeraisonVerifier`` instance based on the ``VERIFIER_NONCE_URL`` environment
variable.  It is the concrete handler used by the MockCA Docker image.

Keeping Veraison-specific logic here (rather than in the base handler) means
upstream changes to ``mock_ca.remote_attestation_handler`` can be merged with
minimal conflicts.
"""

import logging
import os
from typing import Optional

from mock_ca.db_config_vars import RemoteAttestationConfig
from mock_ca.remote_attestation_handler import RemoteAttestationHandler as _BaseHandler
from mock_ca.remote_att_mockca.attestation_verifier import VeraisonVerifier
from resources.remote_att_utils.attest_nonce_freshness_structures import NonceRequestASN1


class RemoteAttestationHandler(_BaseHandler):
    """RemoteAttestationHandler configured with a Veraison verifier.

    On construction the ``VERIFIER_NONCE_URL`` environment variable is read.
    If set, a :class:`VeraisonVerifier` is created and stored as
    ``self._verifier`` so that both nonce fetching and token verification go
    through the Veraison challenge-response API.

    If ``VERIFIER_NONCE_URL`` is not set, ``self._verifier`` remains ``None``
    and the base class falls back to self-generated nonces (when allowed by
    the configuration).
    """

    def __init__(self, config: Optional[RemoteAttestationConfig] = None):
        super().__init__(config)
        verifier_url = os.environ.get("VERIFIER_NONCE_URL", "")
        fetch_timeout = self.nonce_config.fetch_timeout if self.nonce_config else 10

        if verifier_url:
            self._verifier: Optional[VeraisonVerifier] = VeraisonVerifier(
                base_url=verifier_url,
                fetch_timeout=fetch_timeout,
            )
            logging.info("Veraison verifier URL: %s", verifier_url)
        else:
            self._verifier = None
            logging.warning("VERIFIER_NONCE_URL not set; nonces will be self-generated")

    # ── Token verification ────────────────────────────────────────────────────

    def verify_token(
        self,
        token_bytes: bytes,
        media_type: str,
        nonce: Optional[bytes] = None,
    ) -> Optional[str]:
        """Verify *token_bytes* via the configured Veraison verifier.

        :param token_bytes: Raw attestation token bytes.
        :param media_type: Content-Type of the token.
        :param nonce: Nonce bytes used when generating the token; used by
                      Veraison to correlate with the open session.
        :return: EAR JWT string, or ``None`` if verification failed or no
                 verifier is configured.
        """
        if self._verifier is None:
            logging.warning("No verifier configured; skipping token verification")
            return None
        return self._verifier.verify_token(token_bytes, media_type, nonce=nonce)

    # ── Nonce retrieval with hint-based verifier resolution ───────────────────

    def _get_nonce(self, nonce_request: NonceRequestASN1) -> bytes:
        """Get a nonce from Veraison, using a verifier hint when present.

        Priority order:
          1. Use the hint URL / name from the nonce request to create or look
             up a Veraison session.
          2. Fall back to the primary verifier from ``VERIFIER_NONCE_URL``.
          3. Fall back to a self-generated nonce (if allowed).
          4. Return empty bytes (signals the CA cannot provide a nonce).

        :param nonce_request: NonceRequest structure from the CMP GENM body.
        :return: Nonce bytes, or empty bytes if a nonce could not be provided.
        """
        nonce_size = self.nonce_config.min_nonce_length or 32
        timeout = self.nonce_config.fetch_timeout

        if nonce_request["hint"].isValue:
            hint = str(nonce_request["hint"])
            logging.info("Got remote attestation verifier hint: %s", hint)

            if hint.startswith("http"):
                # Hint is a direct URL — use or create a VeraisonVerifier.
                verifier = self._verifier or VeraisonVerifier(
                    base_url=hint, fetch_timeout=timeout
                )
                nonce = verifier.get_nonce(nonce_size)
                if nonce:
                    if self._verifier is None:
                        self._verifier = verifier
                    elif verifier is not self._verifier:
                        self._verifier._sessions.update(verifier._sessions)
                    return nonce
            else:
                # Resolve by name from the configured verifier list.
                url = self._resolve_verifier_url(hint)
                if url:
                    tmp = VeraisonVerifier(base_url=url, fetch_timeout=timeout)
                    nonce = tmp.get_nonce(nonce_size)
                    if nonce:
                        if self._verifier is not None:
                            self._verifier._sessions.update(tmp._sessions)
                        else:
                            self._verifier = tmp
                        return nonce

        # Primary verifier from env var.
        if self._verifier is not None:
            nonce = self._verifier.get_nonce(nonce_size)
            if nonce:
                return nonce

        # Last resort: self-generated nonce or empty.
        if not self.nonce_config.allow_self_generated_nonce:
            return b""

        logging.info("Generating self-generated nonce (%d bytes)", nonce_size)
        return os.urandom(nonce_size)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_verifier_url(self, hint: str) -> Optional[str]:
        """Resolve a verifier hint name to an absolute URL, or return None.

        :param hint: Name of a configured verifier entry.
        :return: The verifier's ``location`` URL, or ``None`` if not found.
        """
        if hint.startswith("http"):
            return hint
        if self.config and self.config.verifiers:
            try:
                entry = self.config.get_verifier(hint)
                if entry and entry.location:
                    return entry.location
            except Exception:  # noqa: BLE001
                pass
        return None
