# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Abstract base class and Veraison implementation for attestation verification.

AttestationVerifier defines the interface for fetching nonces and verifying
attestation tokens. VeraisonVerifier implements this interface using the
Veraison challenge-response API.
"""

import base64
import logging
from abc import ABC, abstractmethod
from typing import Optional
from urllib.parse import urlparse, urlunparse

import requests


class AttestationVerifier(ABC):
    """Abstract interface for attestation token verification.

    Subclasses must implement ``get_nonce`` and ``verify_token``.
    """

    @abstractmethod
    def get_nonce(self, nonce_size: int = 32) -> bytes:
        """Return fresh nonce bytes for use in an attestation challenge.

        :param nonce_size: Requested nonce length in bytes.
        :return: Nonce bytes, or empty bytes on failure.
        """

    @abstractmethod
    def verify_token(self, token_bytes: bytes, media_type: str, nonce: Optional[bytes] = None) -> Optional[str]:
        """Verify an attestation token and return the result as a string.

        :param token_bytes: Raw attestation token bytes.
        :param media_type: Content-Type of the token.
        :param nonce: The nonce bytes that were used when generating the token,
                      so the verifier can correlate with the session.
        :return: Verification result (e.g. EAR JWT string), or None on failure.
        """


class VeraisonVerifier(AttestationVerifier):
    """AttestationVerifier that uses the Veraison challenge-response API.

    Flow:
      1. ``get_nonce`` → POST ``<base_url>/challenge-response/v1/newSession?nonceSize=N``
         Veraison returns a JSON body with a ``nonce`` field (base64) and a
         ``Location`` header pointing to the session resource.
      2. ``verify_token`` → POST ``<session_url>`` with the token body.
         Veraison returns JSON; when ``status`` is ``"complete"`` the ``result``
         field contains the EAR JWT string.

    The session URL is stored by nonce bytes so it can be looked up later.
    """

    def __init__(self, base_url: str, fetch_timeout: int = 10):
        """Initialise the VeraisonVerifier.

        :param base_url: Base URL of the Veraison verifier
                         (e.g. ``https://192.168.110.11:8443``).
        :param fetch_timeout: HTTP request timeout in seconds.
        """
        self.base_url = base_url.rstrip("/")
        self.fetch_timeout = fetch_timeout
        # nonce_bytes → (session_url, media_type)
        self._sessions: dict[bytes, tuple[str, str]] = {}
        logging.info("VeraisonVerifier initialised with base_url=%s", self.base_url)

    # ── Public API ────────────────────────────────────────────────────────────

    def get_nonce(self, nonce_size: int = 32) -> bytes:
        """Request a fresh nonce from Veraison and store the session URL."""
        nonce, session_url, media_type = self._new_session(nonce_size)
        if nonce and session_url:
            self._sessions[nonce] = (session_url, media_type)
            logging.info(
                "Stored Veraison session for nonce (%d bytes): %s (accept: %s)",
                len(nonce),
                session_url,
                media_type,
            )
        return nonce or b""

    def verify_token(self, token_bytes: bytes, media_type: str, nonce: Optional[bytes] = None) -> Optional[str]:
        """Submit *token_bytes* to the Veraison session identified by *nonce*.

        The *media_type* parameter is used as fallback only; the media type
        returned by Veraison during ``newSession`` takes precedence.

        :return: EAR JWT string when Veraison reports ``status == "complete"``,
                 otherwise ``None``.
        """
        session_url = None
        if nonce is not None:
            entry = self._sessions.get(nonce)
            if entry:
                session_url, media_type = entry
                logging.info("Found Veraison session for nonce: %s (media_type: %s)", session_url, media_type)

        if not session_url:
            logging.warning("No Veraison session found for nonce; cannot verify token")
            return None

        return self._submit_token(session_url, token_bytes, media_type, nonce)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _new_session(self, nonce_size: int):
        """POST newSession to Veraison and return (nonce_bytes, session_url, media_type).

        ``media_type`` is the first entry from Veraison's ``accept`` list, which
        is the content type the token must be submitted with.

        Returns ``(None, None, "")`` on any failure.
        """
        url = f"{self.base_url}/challenge-response/v1/newSession?nonceSize={nonce_size}"
        logging.info("Requesting nonce from Veraison: POST %s", url)
        try:
            resp = requests.post(url, timeout=self.fetch_timeout, verify=False)
            resp.raise_for_status()
            data = resp.json()
            nonce_b64 = data.get("nonce", "")
            if not nonce_b64:
                logging.warning("Veraison returned empty nonce")
                return None, None, ""
            nonce = base64.b64decode(nonce_b64)

            location = resp.headers.get("Location", "")
            # Resolve relative Location against the newSession request URL so
            # that e.g. "session/{id}" becomes the correct absolute URL.
            from urllib.parse import urljoin
            session_url = urljoin(url, location) if location else ""

            # Use the first accepted media type from Veraison's response.
            accept_list = data.get("accept", [])
            media_type = accept_list[0] if accept_list else ""
            logging.info(
                "Got nonce from Veraison (%d bytes), session: %s, media_type: %s",
                len(nonce),
                session_url,
                media_type,
            )
            return nonce, session_url, media_type
        except Exception as exc:
            logging.error("Failed to get nonce from Veraison: %s", exc)
            return None, None, ""

    def _submit_token(
        self, session_url: str, token_bytes: bytes, media_type: str, nonce: Optional[bytes]
    ) -> Optional[str]:
        """POST *token_bytes* to *session_url* and return the EAR JWT or None."""
        logging.info("Submitting attestation token to Veraison: POST %s", session_url)
        try:
            resp = requests.post(
                session_url,
                data=token_bytes,
                headers={
                    "Content-Type": media_type,
                    "Accept": "application/vnd.veraison.challenge-response-session+json",
                },
                timeout=self.fetch_timeout,
                verify=False,
            )
            resp.raise_for_status()
            data = resp.json()
            logging.info("Veraison verification status: %s", data.get("status"))
            if data.get("status") == "complete":
                ear_jwt = data.get("result", "")
                logging.info("Got EAR JWT from Veraison (%d bytes)", len(ear_jwt))
                if nonce is not None:
                    self._sessions.pop(nonce, None)
                return ear_jwt
            logging.warning("Veraison verification not complete: %s", data)
            return None
        except Exception as exc:
            logging.error("Failed to verify token with Veraison: %s", exc)
            return None

    def _absolute_url(self, location: str) -> str:
        """Convert a relative *location* path to an absolute URL using ``self.base_url``."""
        parsed = urlparse(self.base_url)
        return urlunparse((parsed.scheme, parsed.netloc, location, "", "", ""))
