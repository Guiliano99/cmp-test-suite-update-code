# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Abstract base class for attestation token verification.

``AttestationVerifier`` defines the interface that all concrete verifier
implementations must satisfy.  The Veraison implementation lives in
``mock_ca.remote_att_mockca.attestation_verifier`` to keep this module
free of environment-specific dependencies.
"""

from abc import ABC, abstractmethod
from typing import Optional


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
    def verify_token(
        self,
        token_bytes: bytes,
        media_type: str,
        nonce: Optional[bytes] = None,
    ) -> Optional[str]:
        """Verify an attestation token and return the result as a string.

        :param token_bytes: Raw attestation token bytes.
        :param media_type: Content-Type of the token.
        :param nonce: The nonce bytes that were used when generating the token,
                      so the verifier can correlate with the session.
        :return: Verification result (e.g. EAR JWT string), or None on failure.
        """
