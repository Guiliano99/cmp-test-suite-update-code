# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""CMP IR-side adapter for RATS evidence over the :mod:`libattest.ra` engine.

The reusable bundle-verification flow — decode the ``AttestationBundle``, consume
each statement's nonce, resolve its profile, submit to the verifier, run the
optional reference-value check, aggregate the verdicts + EAR JWTs, and resolve
the EAR certificate-extension encoding — lives in
:class:`libattest.ra.RemoteAttestationEngine`.  The verifier HTTP client comes
from each profile (the default :class:`~libattest.ra.VeraisonVerifierClient`).

The MockCA keeps only the CMP/CA glue:

1. **Bundle extraction** from the CMP carrier — ``certTemplate.extensions``
   (cr/ir/kur) or PKCS#10 CSR attributes (p10cr) — yielding the
   ``AttestationBundle`` DER.
2. **Transaction id** extraction.
3. ``engine.verify_bundle(bundle_der, tx_id)`` and CMP status mapping
   (not-accepted → :class:`BadMessageCheck`).
4. **EAR-extension handoff** to the normal certificate builder.

The per-statement nonce store / profile registry / verifier client / EAR
extension encoder all live in the engine now (shared with the GenM leg via the
same ``RemoteAttestationHandler``), so this module no longer owns any of them.
"""

from __future__ import annotations

import logging
import os
from typing import Optional, Tuple

from libattest.ra import RemoteAttestationEngine
from libattest.x509 import encode_ear_extension as _libattest_encode_ear_extension
from pyasn1_alt_modules import rfc5280

from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import encode_to_der

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# OID (id-aa-attestation) for the attestation attribute in
# certTemplate.extensions or CSR attributes.
ATTESTATION_OID = "1.2.840.113549.1.9.16.2.59"

# Fallback EAR-extension OID used only when no profile resolves for a statement.
# The CMW-vs-raw choice and the env-driven default live in :mod:`libattest.x509`
# / the ``libattest.ra`` profile; this module no longer encodes the EAR
# extension itself except via this fallback.
_DEFAULT_EAR_EXT_OID = os.environ.get("EAR_OID", "1.7.6.5.123")


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------


class RatsHandler:
    """CMP IR-side adapter: extract a bundle, verify it, and return its EAR.

    Holds ``remote_att_handler`` — a
    :class:`~mock_ca.remote_attestation_handler.RemoteAttestationHandler` whose
    ``engine`` attribute (a :class:`libattest.ra.RemoteAttestationEngine`) owns
    nonce consumption, profile resolution, and verifier submission.  The same
    engine is shared with the GenM leg, so the nonce a GenM issued is the nonce
    the IR consumes.

    Construction takes ``remote_att_handler=None`` because the MockCA wires the
    handler up after the GenM-side machinery exists (see ``ca_handler.py``).
    """

    def __init__(self, remote_att_handler=None) -> None:
        """Initialise the adapter.

        :param remote_att_handler: a ``RemoteAttestationHandler`` whose
            ``engine`` drives verification.  May be ``None`` at construction;
            assigned by the CA wiring code once the GenM handler exists.
        """
        self.remote_att_handler = remote_att_handler

    # ── Public API ────────────────────────────────────────────────────────────

    def verify_bundle(self, pki_message: PKIMessageTMP) -> Optional[Tuple[str, bytes]]:
        """Verify every statement in the bundle; return the EAR X.509 extension to embed.

        Call this BEFORE building the CMP CP response so a failure raises
        :class:`resources.exceptions.BadMessageCheck` and the outer CMP layer
        returns a rejection (no certificate issued).

        :param pki_message: The incoming CMP CR / IR / KUR / P10CR.
        :return: ``(extn_oid_dot, extn_value_der)`` for the first affirming
            statement, ready for the normal certificate builder; ``None`` when
            the request carries no evidence (soft skip).
        :raises BadMessageCheck: if the engine did not accept the bundle.
        """
        from resources.exceptions import BadMessageCheck  # noqa: PLC0415

        evidence_count = self.evidence_count(pki_message)
        if evidence_count == 0:
            logging.debug("RatsHandler: no evidence in request — skip")
            return None
        if evidence_count != 1:
            raise BadMessageCheck(
                f"RatsHandler: expected exactly one id-aa-attestation carrier, found {evidence_count}."
            )

        bundle_der = self._extract_bundle_der(pki_message)
        if bundle_der is None:
            raise BadMessageCheck("RatsHandler: evidence carrier did not contain an attestation bundle.")

        engine = self._engine()
        if engine is None:
            raise BadMessageCheck(
                "RatsHandler: evidence is present but no RemoteAttestationEngine is configured — cannot dispatch."
            )

        tx_id = bytes(pki_message["header"]["transactionID"])

        # The engine owns the whole flow: per-statement nonce consume → profile
        # resolve → verifier submit (forwarding respInfo JSON for the quote leg,
        # sessionId + subject pubkey for the key-attest leg) → reference check →
        # aggregate → resolve the EAR extension encoding. The subject SPKI is
        # threaded unconditionally; quote/jwt profiles ignore it (engine only adds
        # it to the submit body when the profile carries a session).
        outcome = engine.verify_bundle(bundle_der, tx_id, pubkey=self._extract_subject_pubkey(pki_message))

        if not outcome.accepted:
            failure = outcome.first_failure
            if failure is not None:
                reason = "; ".join(failure.errors) or failure.status.value
            else:
                reason = "no statements verified"
            raise BadMessageCheck(f"RatsHandler: bundle verification rejected for tx={tx_id.hex()}: {reason}")

        logging.info(
            "RatsHandler: verified %d statement(s) for tx=%s",
            len(outcome.result.per_statement),
            tx_id.hex(),
        )

        # The cert extension carries one EAR JWT; for multi-statement bundles the
        # first affirming one is used (the others have already been validated).
        ear_extension = outcome.first_ear_extension
        if ear_extension is None:
            # Should not happen for an accepted bundle (a profile resolved to
            # verify it, so it resolves again to encode it) — stay defensive
            # rather than silently drop the extension.
            ear_jwt = outcome.first_ear
            if ear_jwt is None:
                raise BadMessageCheck("RatsHandler: accepted bundle did not produce an EAR.")
            ear_extension = _libattest_encode_ear_extension(ear_jwt, oid=_DEFAULT_EAR_EXT_OID)
        return ear_extension

    # ── Engine accessor ────────────────────────────────────────────────────────

    def _engine(self) -> Optional[RemoteAttestationEngine]:
        """Return the shared :class:`RemoteAttestationEngine`, or ``None``.

        The engine hangs off the wired :class:`RemoteAttestationHandler`.  When
        no handler is wired up yet (early CA startup, evidence-free probes) this
        returns ``None`` and callers fall back to the libattest defaults.
        """
        return getattr(self.remote_att_handler, "engine", None)

    # ── Evidence extraction (CMP carrier) ──────────────────────────────────────

    def _extract_bundle_der(self, pki_message: PKIMessageTMP) -> Optional[bytes]:
        """Return the raw ``AttestationBundle`` DER from the CMP carrier."""
        body_name = pki_message["body"].getName()
        if body_name == "p10cr":
            return self._extract_from_csr_attributes(pki_message)
        if body_name in ("cr", "ir", "kur"):
            return self._extract_from_cert_template_extensions(pki_message)
        logging.debug("RatsHandler: unsupported body type '%s', skipping", body_name)
        return None

    @staticmethod
    def evidence_count(pki_message: PKIMessageTMP) -> int:
        """Return the number of id-aa-attestation carriers in a CMP request."""
        body_name = pki_message["body"].getName()
        try:
            if body_name == "p10cr":
                cri = pki_message["body"]["p10cr"]["certificationRequestInfo"]
                if not cri["attributes"].isValue:
                    return 0
                return sum(
                    max(1, len(attr["attrValues"]))
                    for attr in cri["attributes"]
                    if str(attr["attrType"]) == ATTESTATION_OID
                )
            if body_name in ("cr", "ir", "kur"):
                return sum(
                    sum(
                        str(ext["extnID"]) == ATTESTATION_OID
                        for ext in cert_req_msg["certReq"]["certTemplate"]["extensions"]
                    )
                    for cert_req_msg in pki_message["body"][body_name]
                    if cert_req_msg["certReq"]["certTemplate"]["extensions"].isValue
                )
        except Exception as exc:  # noqa: BLE001
            logging.debug("RatsHandler.evidence_count: scan failed: %s", exc)
        return 0

    @staticmethod
    def has_evidence(pki_message: PKIMessageTMP) -> bool:
        """Return whether the CMP request carries any attestation evidence."""
        return RatsHandler.evidence_count(pki_message) > 0

    @staticmethod
    def _extract_from_cert_template_extensions(pki_message: PKIMessageTMP) -> Optional[bytes]:
        """Return ``AttestationBundle`` DER from ``certTemplate.extensions``."""
        try:
            body_name = pki_message["body"].getName()
            cert_req = pki_message["body"][body_name][0]["certReq"]
            extensions = cert_req["certTemplate"]["extensions"]
            if not extensions.isValue:
                return None
            for ext in extensions:
                if str(ext["extnID"]) == ATTESTATION_OID:
                    bundle_der = bytes(ext["extnValue"])
                    logging.info(
                        "RatsHandler: found evidence in certTemplate.extensions (%d bytes)",
                        len(bundle_der),
                    )
                    return bundle_der
        except Exception as exc:  # noqa: BLE001
            logging.warning("RatsHandler: failed to extract from certTemplate.extensions: %s", exc)
        return None

    @staticmethod
    def _extract_from_csr_attributes(pki_message: PKIMessageTMP) -> Optional[bytes]:
        """Return ``AttestationBundle`` DER from PKCS#10 CSR attributes."""
        try:
            csr = pki_message["body"]["p10cr"]
            cri = csr["certificationRequestInfo"]
            if not cri["attributes"].isValue:
                return None
            for attr in cri["attributes"]:
                if str(attr["attrType"]) == ATTESTATION_OID:
                    values = attr["attrValues"]
                    if len(values) == 0:
                        continue
                    bundle_der = values[0].asOctets()
                    logging.info(
                        "RatsHandler: found evidence in CSR attributes (%d bytes)",
                        len(bundle_der),
                    )
                    return bundle_der
        except Exception as exc:  # noqa: BLE001
            logging.warning("RatsHandler: failed to extract from CSR attributes: %s", exc)
        return None

    @staticmethod
    def _extract_subject_pubkey(pki_message: PKIMessageTMP) -> Optional[bytes]:
        """Return the to-be-certified SubjectPublicKeyInfo DER from the CMP carrier.

        Mirrors :meth:`_extract_bundle_der`'s body switch: the CSR's
        ``subjectPublicKeyInfo`` (p10cr) or ``certTemplate.publicKey`` (cr/ir/kur).
        Crypto-free pyasn1 extraction — the bytes are threaded into
        ``engine.verify_bundle(pubkey=...)`` so the key-attest verifier can bind the
        certified TPM key to the key being enrolled (design C6 / Check-2).  Returns
        ``None`` when the carrier has no public key (quote/jwt profiles ignore it).

        ``CertTemplate.publicKey`` (RFC 4211) is ``[6] IMPLICIT SubjectPublicKeyInfo``:
        re-encoding the decoded component standalone reuses its current (implicit,
        context-tagged) ``tagSet``, producing a ``[6]``-tagged TLV instead of the
        universal ``SEQUENCE`` a plain SubjectPublicKeyInfo consumer (e.g.
        ``cryptography.hazmat.primitives.serialization.load_der_public_key``)
        expects. ``libattest.x509.unwrap_context_tag`` does not fix this either: its
        explicit-vs-implicit heuristic (peek at the first inner byte) misfires here
        because ``SubjectPublicKeyInfo.algorithm`` is itself a SEQUENCE, so it
        returns just the inner ``AlgorithmIdentifier`` TLV and silently drops the
        ``subjectPublicKey`` bits. Rebuilding a "naked" ``rfc5280.SubjectPublicKeyInfo``
        from the decoded field *values* re-derives a correctly-tagged encoding
        regardless of how the source field was tagged. p10cr's
        ``certificationRequestInfo.subjectPublicKeyInfo`` is untagged already, so it
        is returned as-is.
        """
        try:
            body_name = pki_message["body"].getName()
            if body_name == "p10cr":
                spki = pki_message["body"]["p10cr"]["certificationRequestInfo"]["subjectPublicKeyInfo"]
                if not spki.isValue:
                    return None
                return bytes(encode_to_der(spki))
            if body_name in ("cr", "ir", "kur"):
                spki = pki_message["body"][body_name][0]["certReq"]["certTemplate"]["publicKey"]
                if not spki.isValue:
                    return None
                naked = rfc5280.SubjectPublicKeyInfo()
                naked["algorithm"] = spki["algorithm"]
                naked["subjectPublicKey"] = spki["subjectPublicKey"]
                return bytes(encode_to_der(naked))
            return None
        except Exception as exc:  # noqa: BLE001
            logging.debug("RatsHandler._extract_subject_pubkey: %s", exc)
            return None


__all__ = [
    "ATTESTATION_OID",
    "RatsHandler",
]
