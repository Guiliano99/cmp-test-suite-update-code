# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""EAR/EAT verifier for the RATS demonstration environment.

Provides :class:`EarEatVerifier`, which covers two complementary tasks:

**EAT side (outgoing token, produced by the attester)**
  - Extract the ``eat_nonce`` claim from a JWT-serialised EAT so the CA can
    correlate the token with the nonce it previously issued.

**EAR side (incoming result, produced by the Veraison verifier)**
  - Decode the EAR JWT returned by Veraison after evidence submission.
  - Validate structural integrity (three-part JWT, decodable payload).
  - Optionally verify the nonce claim round-trips correctly.
  - Surface the per-submodule trust tier and the consolidated trust vector so
    that policy decisions can be made without re-parsing the raw JWT.

Terminology follows:
  - draft-ietf-rats-architecture   — RATS overall architecture
  - draft-ietf-rats-eat            — Entity Attestation Token (EAT)
  - draft-ietf-rats-ar4si          — Attestation Results for Secure Interactions (EAR)
"""

import base64
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ── Trust tier constants (draft-ietf-rats-ar4si §2.3) ─────────────────────────

TRUST_TIER_AFFIRMING = "affirming"
TRUST_TIER_WARNING = "warning"
TRUST_TIER_CONTRAINDICATED = "contraindicated"
TRUST_TIER_NONE = "none"

# Ordered from most to least trusted — used for consolidation across submods.
_TRUST_TIER_ORDER: List[str] = [
    TRUST_TIER_CONTRAINDICATED,
    TRUST_TIER_WARNING,
    TRUST_TIER_AFFIRMING,
    TRUST_TIER_NONE,
]


# ── Data containers ───────────────────────────────────────────────────────────


@dataclass
class SubmodResult:
    """Parsed result for a single EAR submodule.

    Attributes:
        name:         Submodule name as it appears in the ``submods`` claim.
        trust_tier:   Overall trust tier for this submodule
                      (``"affirming"``, ``"warning"``, ``"contraindicated"``,
                      or ``"none"``).
        trust_vector: Raw ``trust-vector`` mapping (claim → numeric value) as
                      defined in draft-ietf-rats-ar4si Appendix A, or an empty
                      dict when absent.
        raw:          Full raw dict for this submodule taken straight from the
                      JWT payload.
    """

    name: str
    trust_tier: str = TRUST_TIER_NONE
    trust_vector: Dict[str, int] = field(default_factory=dict)
    raw: Dict = field(default_factory=dict)


@dataclass
class EarResult:
    """Decoded and validated EAR JWT.

    Attributes:
        issuer:         ``iss`` claim value (the verifier identity).
        issued_at:      ``iat`` claim value (Unix timestamp), or ``None``.
        nonce:          ``eat_nonce`` bytes decoded from the EAR payload,
                        or ``None`` when the claim is absent.
        submods:        Per-submodule results keyed by submodule name.
        consolidated_tier: Worst-case trust tier across all submodules.
        raw_payload:    Full decoded payload dict for caller inspection.
    """

    issuer: str = ""
    issued_at: Optional[int] = None
    nonce: Optional[bytes] = None
    submods: Dict[str, SubmodResult] = field(default_factory=dict)
    consolidated_tier: str = TRUST_TIER_NONE
    raw_payload: Dict = field(default_factory=dict)

    @property
    def is_affirming(self) -> bool:
        """Return ``True`` when every submodule is ``affirming``."""
        return self.consolidated_tier == TRUST_TIER_AFFIRMING

    @property
    def is_actionable(self) -> bool:
        """Return ``True`` when the EAR is affirming or carries a warning."""
        return self.consolidated_tier in (TRUST_TIER_AFFIRMING, TRUST_TIER_WARNING)


# ── Main verifier class ───────────────────────────────────────────────────────


class EarEatVerifier:
    """Verify EAR (Entity Attestation Result) and EAT (Entity Attestation Token) JWTs.

    This class is intentionally stateless — all methods are pure functions on
    their inputs so that an instance can safely be shared across requests.

    Signature verification is *not* performed here because the Veraison
    challenge-response protocol already guarantees authenticity of the EAR
    (it is returned directly over TLS from Veraison, not forwarded by the
    attester).  If standalone signature verification is required in future the
    ``verify_ear_signature`` hook can be extended.
    """

    # ── EAT helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def extract_eat_nonce(token_bytes: bytes) -> Optional[bytes]:
        """Return the ``eat_nonce`` from a JWT-serialised EAT.

        The nonce field is used by the CA to correlate the attestation token
        with the nonce it previously issued via the GENM/GENP exchange.

        Accepts both ``str`` nonce values (base64url-encoded) and ``list``
        values (multi-nonce; only the first element is returned).

        :param token_bytes: Raw EAT bytes (a compact-serialised JWT).
        :return: Nonce bytes, or ``None`` if the claim is absent or the token
                 is not a three-part JWT.
        """
        payload = EarEatVerifier._decode_jwt_payload(token_bytes)
        if payload is None:
            return None

        nonce_val = payload.get("eat_nonce")
        if nonce_val is None:
            logging.debug("EarEatVerifier: eat_nonce claim absent in EAT payload")
            return None

        # draft-ietf-rats-eat §4.1: eat_nonce may be a single string or a list.
        if isinstance(nonce_val, list):
            nonce_val = nonce_val[0] if nonce_val else None
        if not nonce_val:
            return None

        try:
            return EarEatVerifier._b64url_decode(nonce_val)
        except Exception as exc:  # noqa: BLE001
            logging.warning("EarEatVerifier: could not decode eat_nonce: %s", exc)
            return None

    @staticmethod
    def verify_eat_nonce(token_bytes: bytes, expected_nonce: bytes) -> bool:
        """Return ``True`` when the EAT's ``eat_nonce`` matches *expected_nonce*.

        :param token_bytes: Raw EAT bytes.
        :param expected_nonce: The nonce bytes that were originally issued by
                               the CA.
        :return: ``True`` on a match, ``False`` otherwise.
        """
        actual = EarEatVerifier.extract_eat_nonce(token_bytes)
        if actual is None:
            logging.warning("EarEatVerifier: eat_nonce missing in EAT; nonce check failed")
            return False
        match = actual == expected_nonce
        if not match:
            logging.warning(
                "EarEatVerifier: eat_nonce mismatch (got %s, expected %s)",
                actual.hex(),
                expected_nonce.hex(),
            )
        return match

    # ── EAR parsing ───────────────────────────────────────────────────────────

    @staticmethod
    def parse_ear(ear_jwt: str) -> Optional[EarResult]:
        """Decode an EAR JWT and return a structured :class:`EarResult`.

        The EAR payload is expected to follow draft-ietf-rats-ar4si.  Key
        claims extracted:

        * ``iss``     — verifier identity
        * ``iat``     — issuance time
        * ``eat_nonce`` — nonce echo (may be absent in EAR; see spec §3.2)
        * ``submods`` — per-sub-environment trust tiers and trust vectors

        :param ear_jwt: Compact-serialised JWT string (``header.payload.sig``).
        :return: :class:`EarResult`, or ``None`` if the JWT cannot be decoded.
        """
        payload = EarEatVerifier._decode_jwt_payload(ear_jwt.encode())
        if payload is None:
            return None

        result = EarResult(raw_payload=payload)

        result.issuer = payload.get("iss", "")
        result.issued_at = payload.get("iat")

        nonce_raw = payload.get("eat_nonce")
        if nonce_raw is not None:
            if isinstance(nonce_raw, list):
                nonce_raw = nonce_raw[0] if nonce_raw else None
            if nonce_raw:
                try:
                    result.nonce = EarEatVerifier._b64url_decode(nonce_raw)
                except Exception as exc:  # noqa: BLE001
                    logging.warning("EarEatVerifier: could not decode EAR eat_nonce: %s", exc)

        # Parse per-submodule results from the ``submods`` claim.
        submods_raw = payload.get("submods", {})
        for submod_name, submod_data in submods_raw.items():
            if not isinstance(submod_data, dict):
                continue
            sr = SubmodResult(
                name=submod_name,
                trust_tier=submod_data.get("ear.trust-tier", TRUST_TIER_NONE),
                trust_vector=submod_data.get("ear.trust-vector", {}),
                raw=submod_data,
            )
            result.submods[submod_name] = sr
            logging.debug(
                "EarEatVerifier: submod=%s tier=%s vector=%s",
                submod_name,
                sr.trust_tier,
                sr.trust_vector,
            )

        result.consolidated_tier = EarEatVerifier._consolidate_tier(result.submods)
        logging.info(
            "EarEatVerifier: EAR parsed — iss=%s submods=%d consolidated_tier=%s",
            result.issuer,
            len(result.submods),
            result.consolidated_tier,
        )
        return result

    @staticmethod
    def verify_ear_nonce(ear_jwt: str, expected_nonce: bytes) -> bool:
        """Return ``True`` when the EAR's ``eat_nonce`` matches *expected_nonce*.

        Note: the EAR spec does not require the nonce to be echoed back in the
        EAR itself (it is bound via the session URL instead).  This method is
        provided for implementations that do echo the nonce.

        :param ear_jwt: EAR JWT string.
        :param expected_nonce: The nonce originally issued by the CA.
        :return: ``True`` on a match or when the EAR carries no nonce claim.
        """
        result = EarEatVerifier.parse_ear(ear_jwt)
        if result is None:
            return False
        if result.nonce is None:
            logging.debug("EarEatVerifier: EAR has no eat_nonce claim; skipping nonce check")
            return True
        match = result.nonce == expected_nonce
        if not match:
            logging.warning(
                "EarEatVerifier: EAR nonce mismatch (got %s, expected %s)",
                result.nonce.hex(),
                expected_nonce.hex(),
            )
        return match

    @staticmethod
    def get_consolidated_tier(ear_jwt: str) -> str:
        """Return the worst-case trust tier across all EAR submodules.

        :param ear_jwt: EAR JWT string.
        :return: One of ``"affirming"``, ``"warning"``, ``"contraindicated"``,
                 ``"none"``, or ``"unknown"`` when parsing fails.
        """
        result = EarEatVerifier.parse_ear(ear_jwt)
        if result is None:
            return "unknown"
        return result.consolidated_tier

    @staticmethod
    def is_affirming(ear_jwt: str) -> bool:
        """Return ``True`` when every submodule in the EAR is ``"affirming"``.

        :param ear_jwt: EAR JWT string.
        """
        return EarEatVerifier.get_consolidated_tier(ear_jwt) == TRUST_TIER_AFFIRMING

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _decode_jwt_payload(token: bytes) -> Optional[Dict]:
        """Decode the middle (payload) segment of a compact JWT without verifying signature.

        :param token: Raw token bytes (JWT or EAT compact serialisation).
        :return: Decoded JSON payload dict, or ``None`` on any failure.
        """
        try:
            if isinstance(token, str):
                token = token.encode()
            parts = token.split(b".")
            if len(parts) < 2:
                logging.warning("EarEatVerifier: token is not a compact JWT (< 2 parts)")
                return None
            return json.loads(EarEatVerifier._b64url_decode(parts[1]))
        except Exception as exc:  # noqa: BLE001
            logging.warning("EarEatVerifier: failed to decode JWT payload: %s", exc)
            return None

    @staticmethod
    def _b64url_decode(value) -> bytes:
        """Decode a base64url-encoded string, adding padding as needed."""
        if isinstance(value, str):
            value = value.encode()
        # base64url uses - and _ instead of + and /; strip any existing padding first.
        value = value.rstrip(b"=").replace(b"-", b"+").replace(b"_", b"/")
        padding = (4 - len(value) % 4) % 4
        return base64.b64decode(value + b"=" * padding)

    @staticmethod
    def _consolidate_tier(submods: Dict[str, SubmodResult]) -> str:
        """Return the worst-case trust tier across *submods*.

        The ordering from worst to best is:
        ``contraindicated`` > ``warning`` > ``affirming`` > ``none``.

        An empty submodule map returns ``"none"``.
        """
        if not submods:
            return TRUST_TIER_NONE

        # Iterate the ordered list and return the first tier present in any submod.
        present = {sr.trust_tier for sr in submods.values()}
        for tier in _TRUST_TIER_ORDER:
            if tier in present:
                return tier
        return TRUST_TIER_NONE
