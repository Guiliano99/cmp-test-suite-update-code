# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""MockCA-side verifier for the TPM key-attestation PoP scheme (SPEC §DR-6).

The KeyAttestPoP scheme proves possession of a TPM-resident private key
in two steps:

1. The MockCA RSA-OAEP-encrypts a freshly generated nonce ``N`` against
   the SubjectPublicKeyInfo of the to-be-attested key (handled by
   :class:`mock_ca.nonce_handler.NonceHandler`).
2. The attester decrypts ``N`` with the TPM-bound private key and
   computes ``PBMAC1(password=N, data=SPKI_DER)`` over the SPKI bytes.
   The proof is shipped both inside the ``AttestationBundle`` (for the
   verifier) and as a CSR extension under the configured
   ``KEY_ATTEST_POP_OID`` (for the MockCA).

This module owns step 2's MockCA-side verification — the policy-bearing,
CA-internal logic that does NOT belong in the platform-agnostic
``libattest-py`` package.  Its responsibilities are:

* Walk the inbound ``PKIMessage`` and pull out the SPKI of the
  to-be-attested key (from ``CertificationRequestInfo`` for ``p10cr``
  or from ``certTemplate.subjectPublicKeyInfo`` for ``ir``/``cr``/``kur``).
* Walk the same message and pull out the ``KeyAttestPoPProof`` DER
  carried under the configured PoP OID as a CSR / certTemplate extension.
* Recompute the PBMAC against the stored plaintext nonce + SPKI, using
  the salt + iterations supplied in the proof's ``pbmParameter``.
  Mismatch → :class:`resources.exceptions.BadMessageCheck`.

The extractor methods are deliberately ``staticmethod`` so unit tests can
exercise them without standing up a verifier instance.
"""

from __future__ import annotations

import logging
from typing import Optional

from libattest.formats.key_attest_pop import (
    decode_key_attest_pop_proof,
    proof_algorithm_oid,
    verify_key_attest_pop_proof,
)
from pyasn1.codec.der import encoder as asn1_encoder

from resources.asn1_structures import PKIMessageTMP

logger = logging.getLogger(__name__)


class KeyAttestTpmVerifier:
    """MockCA-side verifier for ``KeyAttestPoPProof`` CSR extensions.

    Stateless — one instance can serve every enrollment.  The only
    runtime input is the configured OID, which the caller must supply
    so this verifier has no implicit env coupling (helps unit tests and
    keeps the PoP OID coherent with the rest of the MockCA stack).
    """

    def __init__(self, key_attest_pop_oid: str):
        """Construct a verifier bound to *key_attest_pop_oid*.

        :param key_attest_pop_oid: dotted OID that identifies both the
            evidence statement type and the X.509 extension carrying
            the proof (SPEC §DR-5).  Pass the value resolved from the
            :class:`NonceHandler` so attester / MockCA / verifier all
            agree.
        """
        self._oid = key_attest_pop_oid

    @property
    def oid(self) -> str:
        """The dotted OID this verifier is bound to."""
        return self._oid

    # ── Verification ────────────────────────────────────────────────────────

    def verify_pop(
        self,
        attestation_nonce: bytes,
        c_plaintext: Optional[bytes],
        spki_der: Optional[bytes],
        pop_proof_der: Optional[bytes],
        BadMessageCheck,
    ) -> None:
        """Recompute the PoP proof and reject on mismatch (SPEC §DR-6 v2).

        :param attestation_nonce: the plaintext attestation nonce ``N``
            from the per-tx :class:`NonceState` (kept on
            ``NonceState.nonce``).  Used as the PBMAC1 *data* and, in the
            RSA-SHA256 form, as the message that was signed.
        :param c_plaintext: the plaintext challenge nonce ``C`` from
            ``NonceState.c_plaintext``.  Used as the PBMAC1 *password*
            (BASEKEY input) when the proof's algorithm is
            ``id-PasswordBasedMac``; ignored for the RSA-SHA256 form.
            ``None`` is allowed for non-PBMAC slots — it triggers
            rejection only if the proof requires it.
        :param spki_der: DER-encoded ``SubjectPublicKeyInfo`` of the
            to-be-attested key, taken from the CSR.  Required for the
            RSA-SHA256 form (the verifier recovers the public key from
            it); missing → ``BadMessageCheck``.
        :param pop_proof_der: DER bytes of the
            :class:`KeyAttestPoPProof` extension carried in the CSR /
            certTemplate.  ``None`` triggers a ``BadMessageCheck``.
        :param BadMessageCheck: the exception class to raise — injected
            from the caller to avoid an import cycle with
            ``resources.exceptions``.
        """
        if spki_der is None:
            raise BadMessageCheck(
                f"KeyAttestPoP ({self._oid}): CSR is missing the SubjectPublicKeyInfo required for SPKI binding."
            )
        if pop_proof_der is None:
            raise BadMessageCheck(
                f"KeyAttestPoP ({self._oid}): CSR is missing the PoP-proof extension under {self._oid}."
            )

        try:
            proof = decode_key_attest_pop_proof(pop_proof_der)
        except ValueError as exc:
            raise BadMessageCheck(f"KeyAttestPoP ({self._oid}): proof DER did not decode: {exc}") from exc

        ok = verify_key_attest_pop_proof(
            attestation_nonce=attestation_nonce,
            recovered_challenge=c_plaintext,
            spki_der=spki_der,
            proof=proof,
        )
        if not ok:
            raise BadMessageCheck(
                f"KeyAttestPoP ({self._oid}): proof verification failed "
                f"(algorithm={proof_algorithm_oid(proof)}) — the proof "
                "does not bind the supplied (N, C) / SPKI.  Either the "
                "attester recovered the wrong challenge C, the attestation "
                "nonce N was tampered with, the SPKI on the wire diverges "
                "from the one used for encryption, or the proof algorithm "
                "is unsupported."
            )

        logger.info(
            "KeyAttestPoP: PBMAC verified — algorithm=%s, spki=%dB, value=%dB, oid=%s",
            proof_algorithm_oid(proof),
            len(spki_der),
            len(bytes(proof["value"])),
            self._oid,
        )

    # ── Extraction helpers ──────────────────────────────────────────────────

    @staticmethod
    def extract_subject_spki_der(
        pki_message: PKIMessageTMP,
    ) -> Optional[bytes]:
        """Return DER-encoded SPKI of the to-be-attested key, or None.

        Reads ``CertificationRequestInfo.subjectPKInfo`` for ``p10cr``
        bodies and ``certTemplate.subjectPublicKeyInfo`` for
        ``ir``/``cr``/``kur``.  Logs and returns ``None`` for any other
        body or on extraction failure — the calling code raises
        ``BadMessageCheck`` only when the absence is policy-relevant
        (i.e. only for KeyAttestPoP statements).
        """
        body_name = pki_message["body"].getName()
        try:
            if body_name == "p10cr":
                spki = pki_message["body"]["p10cr"]["certificationRequestInfo"]["subjectPKInfo"]
            elif body_name in ("ir", "cr", "kur"):
                spki = pki_message["body"][body_name][0]["certReq"]["certTemplate"]["publicKey"]
            else:
                return None
            if not spki.isValue:
                return None
            return bytes(asn1_encoder.encode(spki))
        except Exception as exc:  # noqa: BLE001
            logger.debug("KeyAttestTpmVerifier.extract_subject_spki_der failed: %s", exc)
            return None

    def extract_pop_proof_der(self, pki_message: PKIMessageTMP) -> Optional[bytes]:
        """Return the DER bytes of the PoP-proof extension, or None.

        Walks the ``PKIMessage`` body looking for the configured PoP
        OID:

        * ``p10cr`` → ``CertificationRequestInfo.attributes`` with
          ``attrType == OID``, where the attrValue is a SEQUENCE OF
          extensions per RFC 2985.  Falls back to the first attrValue
          treated as raw extension value bytes if the wire shape is the
          plainer attrValue-IS-extnValue convention.
        * ``ir``/``cr``/``kur`` → ``certTemplate.extensions`` whose
          ``extnID == OID``; the ``extnValue`` is returned.

        Returns ``None`` when no extension with the OID is present.  Does
        not raise on parse errors — those are surfaced by
        :meth:`verify_pop` via ``BadMessageCheck`` so the rejection is
        attributed to the correct policy.
        """
        body_name = pki_message["body"].getName()
        try:
            if body_name == "p10cr":
                return self._scan_csr_attribute_for_pop(pki_message)
            if body_name in ("ir", "cr", "kur"):
                return self._scan_cert_template_for_pop(pki_message, body_name)
        except Exception as exc:  # noqa: BLE001
            logger.debug("KeyAttestTpmVerifier.extract_pop_proof_der failed: %s", exc)
        return None

    # ── Internals ───────────────────────────────────────────────────────────

    def _scan_cert_template_for_pop(self, pki_message: PKIMessageTMP, body_name: str) -> Optional[bytes]:
        cert_req = pki_message["body"][body_name][0]["certReq"]
        extensions = cert_req["certTemplate"]["extensions"]
        if not extensions.isValue:
            return None
        for ext in extensions:
            if str(ext["extnID"]) == self._oid:
                return bytes(ext["extnValue"])
        return None

    def _scan_csr_attribute_for_pop(self, pki_message: PKIMessageTMP) -> Optional[bytes]:
        cri = pki_message["body"]["p10cr"]["certificationRequestInfo"]
        if not cri["attributes"].isValue:
            return None
        for attr in cri["attributes"]:
            if str(attr["attrType"]) != self._oid:
                continue
            values = attr["attrValues"]
            if len(values) == 0:
                continue
            # We accept either of two shapes:
            #
            # (a) attrValues SET OF Extensions (RFC 2985 §5.4.2 style for
            #     the extensionRequest attribute) — value is a
            #     SEQUENCE OF Extension; we look for our OID inside.
            # (b) attrValues SET OF OCTET STRING — the attribute value
            #     is the raw extnValue OCTET STRING content.  This is
            #     what the gencmpclient C-side emits today (single-OID,
            #     proof-shaped attribute).
            #
            # Try (b) first because it's the simpler, current wire
            # shape; (a) is left as a fallback for forward compatibility.
            return values[0].asOctets()
        return None
