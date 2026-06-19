# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""CMP IR-side adapter for RATS evidence over the :mod:`libattest.ra` engine.

The reusable bundle-verification flow — decode the ``AttestationBundle``, consume
each statement's nonce, resolve its profile, submit to the verifier, run the
optional reference-value check, and aggregate the verdicts + EAR JWTs — lives in
:class:`libattest.ra.RemoteAttestationEngine`.  The verifier HTTP client comes
from each profile (the default :class:`~libattest.ra.VeraisonVerifierClient`).

The MockCA keeps only the CMP/CA glue:

1. **Bundle extraction** from the CMP carrier — ``certTemplate.extensions``
   (cr/ir/kur) or PKCS#10 CSR attributes (p10cr) — yielding the
   ``AttestationBundle`` DER.
2. **Transaction id** extraction.
3. ``engine.verify_bundle(bundle_der, tx_id)`` and CMP status mapping
   (not-accepted → :class:`BadMessageCheck`).
4. **X.509 cert rebuild + EAR-extension embed + re-sign** of the issued cert.

The per-statement nonce store / profile registry / verifier client all live in
the engine now (shared with the GenM leg via the same
``RemoteAttestationHandler``), so this module no longer owns any of them.
"""

from __future__ import annotations

import functools
import logging
import os
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509 import load_der_x509_certificate
import cryptography.x509 as cx509

from libattest.formats.csrattest import (
    decode_attestation_bundle,
    encode_oid_der,
    get_attestation_bundle_certs,
    unwrap_attestation_statement,
)
from libattest.ra import RemoteAttestationEngine
from libattest.x509 import encode_ear_extension as _libattest_encode_ear_extension
from libattest.x509 import unwrap_context_tag

from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import encode_to_der
from resources.certutils import parse_certificate
from resources.cmputils import get_cert_response_from_pkimessage
from resources.convertutils import copy_asn1_certificate
from resources.typingutils import SignKey

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# OID (id-aa-attestation) for the attestation attribute in
# certTemplate.extensions or CSR attributes.
ATTESTATION_OID = "1.2.840.113549.1.9.16.2.59"
EVIDENCE_OID = ATTESTATION_OID   # legacy alias kept for external callers
RATS_TOKEN_OID = ATTESTATION_OID  # legacy alias kept for external callers

# Fallback EAR-extension OID used only when no profile resolves for a statement.
# The CMW-vs-raw choice and the env-driven default live in :mod:`libattest.x509`
# / the ``libattest.ra`` profile; this module no longer encodes the EAR
# extension itself except via the profile's callable (or this fallback).
_DEFAULT_EAR_EXT_OID = os.environ.get("EAR_OID", "1.7.6.5.123")


# ---------------------------------------------------------------------------
# Data containers (kept for source compatibility with external callers/tests)
# ---------------------------------------------------------------------------


@dataclass
class ExtractedStatement:
    """One ``AttestationStatement`` decoded from an ``AttestationBundle``."""

    type_oid: str
    """Dot-form OID of the evidence type (e.g. ``2.23.133.20.1``)."""

    type_oid_der: bytes
    """DER encoding of the OBJECT IDENTIFIER."""

    stmt_bytes: bytes
    """DER substrate of the statement payload (TcgAttest SEQUENCE, or raw JWT
    bytes after the OCTET STRING wrapper is stripped)."""

    is_octet_string_wrapped: bool
    """``True`` when the original bundle wrapped the statement in an OCTET
    STRING (JWT case); ``False`` for direct SEQUENCE encoding (TCG)."""


@dataclass
class ExtractedEvidence:
    """All statements and bundle-level certificates for one IR.

    ``bundle_der`` is the full DER of the ``AttestationBundle`` — the bytes the
    engine verifies.  The ``statements`` list lets callers (and the EAR-encoder
    resolver) inspect the bundle without re-decoding.
    """

    bundle_der: bytes
    statements: List[ExtractedStatement]
    certs_der: List[bytes] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------


class RatsHandler:
    """CMP IR-side adapter: extract a bundle, verify it via the engine, embed EAR.

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

    def verify_and_get_ear(self, pki_message: PKIMessageTMP) -> Optional[str]:
        """Verify every statement in the bundle; return one EAR JWT.

        Call this BEFORE building the CMP CP response so a failure raises
        :class:`resources.exceptions.BadMessageCheck` and the outer CMP layer
        returns a rejection (no certificate issued).

        :param pki_message: The incoming CMP CR / IR / KUR / P10CR.
        :return: EAR JWT string on success; ``None`` when the request carries
            no evidence (soft skip).
        :raises BadMessageCheck: if the engine did not accept the bundle.
        """
        ear_jwt, _ = self._verify_bundle(pki_message)
        return ear_jwt

    def _verify_bundle(
        self, pki_message: PKIMessageTMP
    ) -> tuple[Optional[str], Optional[bytes]]:
        """Backbone of :meth:`verify_and_get_ear`.

        Returns ``(ear_jwt, None)``; the second element is kept for source
        compatibility with earlier KeyAttestPoP callers and is always ``None``
        in the platform-only profile.  ``ear_jwt`` is ``None`` when the request
        carries no evidence.
        """
        from resources.exceptions import BadMessageCheck  # noqa: PLC0415

        bundle_der = self._extract_bundle_der(pki_message)
        if bundle_der is None:
            logging.debug("RatsHandler: no evidence in request — skip")
            return None, None

        engine = self._engine()
        if engine is None:
            raise BadMessageCheck(
                "RatsHandler: evidence is present but no RemoteAttestationEngine "
                "is configured — cannot dispatch."
            )

        tx_id = bytes(pki_message["header"]["transactionID"])

        # The engine owns the whole flow: per-statement nonce consume → profile
        # resolve → verifier submit (forwarding respInfo JSON for the quote leg)
        # → reference check → aggregate.  It drops the per-tx nonce state itself.
        outcome = engine.verify_bundle(bundle_der, tx_id)

        if not outcome.accepted:
            failure = outcome.first_failure
            reason = failure.reason if failure is not None else "no statements verified"
            raise BadMessageCheck(
                f"RatsHandler: bundle verification rejected for tx={tx_id.hex()}: {reason}"
            )

        logging.info(
            "RatsHandler: verified %d statement(s) for tx=%s",
            len(outcome.result.per_statement), tx_id.hex(),
        )

        # The cert extension carries one EAR JWT; for multi-statement bundles use
        # the first affirming one (the others have already been validated).
        return outcome.first_ear, None

    def process_cr_attestation(
        self,
        pki_message: PKIMessageTMP,
        response: PKIMessageTMP,
        ca_key: SignKey,
    ) -> None:
        """Verify evidence and embed the EAR extension (best-effort).

        Does not raise; failures are logged and the certificate is issued
        without an EAR extension.  Use :meth:`verify_and_get_ear` directly when
        a verifier rejection should fail the enrollment with a CMP error.
        """
        try:
            ear_jwt, _ = self._verify_bundle(pki_message)
        except Exception as exc:  # noqa: BLE001
            logging.warning(
                "RatsHandler.process_cr_attestation: verify_and_get_ear raised: %s",
                exc,
            )
            return
        if not ear_jwt:
            return
        self.embed_extensions(
            response,
            ear_jwt,
            ca_key,
            encode_ear_extension=self._ear_encoder_for(pki_message),
        )

    def _ear_encoder_for(
        self, pki_message: PKIMessageTMP
    ) -> Optional[Callable[[str], tuple[str, bytes]]]:
        """Resolve the EAR-extension encoder for *pki_message*'s evidence.

        The EAR JWT corresponds to the first statement in the bundle; this
        returns that statement's profile encoder so the embedded extension uses
        the per-type EAR/CMW choice.  Returns ``None`` (→ libattest default)
        when there is no evidence or no profile.
        """
        engine = self._engine()
        if engine is None:
            return None
        evidence = self.extract_evidence(pki_message)
        if evidence is None or not evidence.statements:
            return None
        profile = engine.profiles.by_statement(evidence.statements[0].type_oid)
        return profile.encode_ear_extension if profile is not None else None

    # ── Engine accessor ────────────────────────────────────────────────────────

    def _engine(self) -> Optional[RemoteAttestationEngine]:
        """Return the shared :class:`RemoteAttestationEngine`, or ``None``.

        The engine hangs off the wired :class:`RemoteAttestationHandler`.  When
        no handler is wired up yet (early CA startup, evidence-free probes) this
        returns ``None`` and callers fall back to the libattest defaults.
        """
        return getattr(self.remote_att_handler, "engine", None)

    # ── Evidence extraction (CMP carrier) ──────────────────────────────────────

    def extract_evidence(self, pki_message: PKIMessageTMP) -> Optional[ExtractedEvidence]:
        """Extract + decode the ``AttestationBundle`` from a CMP request.

        Looks in two places:

        * ``p10cr`` body → ``certificationRequestInfo.attributes``
        * ``cr`` / ``ir`` / ``kur`` body → ``certTemplate.extensions``

        Decoding here is for callers that want to inspect statements (e.g. the
        EAR-encoder resolver); the engine re-decodes the bundle DER itself when
        verifying, so the canonical bytes stay ``ExtractedEvidence.bundle_der``.
        """
        bundle_der = self._extract_bundle_der(pki_message)
        if bundle_der is None:
            return None
        engine = self._engine()
        profiles = engine.profiles if engine is not None else None
        return self._parse_att_bundle_full(bundle_der, profiles)

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
    def has_evidence(pki_message: PKIMessageTMP) -> bool:
        """Lightweight OID scan — does not parse the bundle."""
        body_name = pki_message["body"].getName()
        try:
            if body_name == "p10cr":
                cri = pki_message["body"]["p10cr"]["certificationRequestInfo"]
                if not cri["attributes"].isValue:
                    return False
                return any(str(attr["attrType"]) == ATTESTATION_OID for attr in cri["attributes"])
            if body_name in ("ir", "cr", "kur"):
                cert_req = pki_message["body"][body_name][0]["certReq"]
                exts = cert_req["certTemplate"]["extensions"]
                if not exts.isValue:
                    return False
                return any(str(ext["extnID"]) == ATTESTATION_OID for ext in exts)
        except Exception as exc:  # noqa: BLE001
            logging.debug("RatsHandler.has_evidence: scan failed: %s", exc)
        return False

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
            logging.warning(
                "RatsHandler: failed to extract from certTemplate.extensions: %s", exc
            )
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
            logging.warning(
                "RatsHandler: failed to extract from CSR attributes: %s", exc
            )
        return None

    # ── Bundle parsing (inspection only) ──────────────────────────────────────

    @staticmethod
    def _parse_att_bundle_full(
        bundle_der: bytes,
        profiles=None,
    ) -> Optional[ExtractedEvidence]:
        """Decode an ``AttestationBundle`` into per-statement records.

        Walks every statement; each ``stmt`` open type is unwrapped via the
        profile registered for its statement OID (``profile.unwrap_statement``)
        so the format choice lives in the per-type plugin.  When no profile
        resolves, the libattest default
        :func:`~libattest.formats.csrattest.unwrap_attestation_statement` is
        used.  This is inspection only — the engine re-verifies the raw bundle
        DER independently.

        :param profiles: a :class:`libattest.ra.ProfileRegistry` (or ``None``).
        """
        try:
            bundle = decode_attestation_bundle(bundle_der)
        except ValueError as exc:
            logging.warning("RatsHandler: parse of AttestationBundle failed: %s", exc)
            return None

        if len(bundle["attestations"]) == 0:
            logging.warning("RatsHandler: AttestationBundle has no attestations")
            return None

        statements: List[ExtractedStatement] = []
        for stmt in bundle["attestations"]:
            type_oid = str(stmt["type"])
            type_oid_der = encode_oid_der(stmt["type"])

            stmt_raw: bytes = bytes(stmt["stmt"])
            if not stmt_raw:
                logging.warning("RatsHandler: empty stmt in AttestationStatement (oid=%s)", type_oid)
                continue

            profile = profiles.by_statement(type_oid) if profiles is not None else None
            unwrap = profile.unwrap_statement if profile is not None else unwrap_attestation_statement
            stmt_bytes, is_wrapped = unwrap(stmt_raw)

            statements.append(
                ExtractedStatement(
                    type_oid=type_oid,
                    type_oid_der=type_oid_der,
                    stmt_bytes=stmt_bytes,
                    is_octet_string_wrapped=is_wrapped,
                )
            )

        certs_der: List[bytes] = [
            bytes(encode_to_der(cert)) for cert in get_attestation_bundle_certs(bundle)
        ]

        logging.info(
            "RatsHandler: parsed bundle — %d statement(s), %d cert(s)",
            len(statements), len(certs_der),
        )
        return ExtractedEvidence(
            bundle_der=bundle_der,
            statements=statements,
            certs_der=certs_der,
        )

    # ── Cert extension embedding ─────────────────────────────────────────────

    @classmethod
    def embed_ear_extension(
        cls,
        response: PKIMessageTMP,
        ear_jwt: str,
        ca_key: SignKey,
        *,
        encode_ear_extension: Optional[Callable[[str], tuple[str, bytes]]] = None,
    ) -> None:
        """Backward-compatible shim — embed only the EAR JWT extension.

        Equivalent to :meth:`embed_extensions` with ``pop_proof_der=None``; kept
        so external callers (and the legacy non-PoP enrollment path) compile.
        """
        cls.embed_extensions(
            response,
            ear_jwt,
            ca_key,
            pop_proof_der=None,
            encode_ear_extension=encode_ear_extension,
        )

    @staticmethod
    def embed_extensions(
        response: PKIMessageTMP,
        ear_jwt: str,
        ca_key: SignKey,
        *,
        pop_proof_der: Optional[bytes] = None,
        encode_ear_extension: Optional[Callable[[str], tuple[str, bytes]]] = None,
    ) -> None:
        """Add the EAR JWT (and optionally the KeyAttestPoP proof) extensions.

        The certificate is extracted from the CP response, rebuilt with the new
        extension(s) using ``cryptography``, re-signed with *ca_key*, and copied
        back into the response in place.

        :param response: the CMP CP response containing the issued cert.
        :param ear_jwt: the compact-serialised EAR JWT string.
        :param ca_key: CA private key used to re-sign the rebuilt cert.
        :param pop_proof_der: when supplied, the DER bytes of the
            ``KeyAttestPoPProof`` are copied verbatim onto the issued cert as an
            X.509 v3 extension under :func:`resolve_key_attest_pop_oid`
            (lazy import; the platform-only libattest tree may not ship it).
            ``None`` for non-PoP enrollments.
        :param encode_ear_extension: ``(ear_jwt) -> (extn_oid_dot, extn_value_der)``
            callable selecting the EAR extension OID + value encoding.  Normally
            the profile's ``encode_ear_extension``; when ``None`` the libattest
            default bound to the env ``EAR_OID`` is used.  The CMW-vs-raw choice
            lives entirely in the callable — this method never branches on the OID.
        """
        if encode_ear_extension is None:
            encode_ear_extension = functools.partial(
                _libattest_encode_ear_extension, oid=_DEFAULT_EAR_EXT_OID
            )
        try:
            cert_resp = get_cert_response_from_pkimessage(response, response_index=0)
            cert_choice = cert_resp["certifiedKeyPair"]["certOrEncCert"]["certificate"]

            # cert_choice carries CertOrEncCert's context tag from the CHOICE;
            # unwrap it so the DER is a plain Certificate TLV.
            cmp_cert_der = unwrap_context_tag(encode_to_der(cert_choice))
            x509_cert = load_der_x509_certificate(cmp_cert_der)

            existing_extensions = list(x509_cert.extensions)

            ear_oid_dot, ear_value = encode_ear_extension(ear_jwt)
            ear_oid = cx509.ObjectIdentifier(ear_oid_dot)
            existing_extensions.append(cx509.Extension(
                oid=ear_oid,
                critical=False,
                value=cx509.UnrecognizedExtension(ear_oid, ear_value),
            ))

            if pop_proof_der is not None:
                from libattest.formats.key_attest_pop import (  # noqa: PLC0415
                    resolve_key_attest_pop_oid,
                )

                pop_oid = cx509.ObjectIdentifier(resolve_key_attest_pop_oid())
                existing_extensions.append(cx509.Extension(
                    oid=pop_oid,
                    critical=False,
                    value=cx509.UnrecognizedExtension(pop_oid, pop_proof_der),
                ))

            builder = (
                cx509.CertificateBuilder()
                .subject_name(x509_cert.subject)
                .issuer_name(x509_cert.issuer)
                .public_key(x509_cert.public_key())
                .serial_number(x509_cert.serial_number)
                .not_valid_before(x509_cert.not_valid_before_utc)
                .not_valid_after(x509_cert.not_valid_after_utc)
            )
            for ext in existing_extensions:
                try:
                    builder = builder.add_extension(ext.value, critical=ext.critical)
                except Exception:  # noqa: BLE001
                    pass

            # Re-sign with the CA key.  ca_key may be Ed25519 or another scheme;
            # cryptography handles the dispatch internally.
            if isinstance(ca_key, Ed25519PrivateKey):
                rebuilt = builder.sign(private_key=ca_key, algorithm=None)
            else:
                rebuilt = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

            new_cmp_cert = parse_certificate(
                rebuilt.public_bytes(serialization.Encoding.DER)
            )
            copy_asn1_certificate(new_cmp_cert, cert_choice)
            embedded = [ear_oid_dot]
            if pop_proof_der is not None:
                from libattest.formats.key_attest_pop import (  # noqa: PLC0415
                    resolve_key_attest_pop_oid,
                )

                embedded.append(resolve_key_attest_pop_oid())
            logging.info(
                "RatsHandler: embedded extension(s) on issued cert: %s",
                ", ".join(embedded),
            )
        except Exception as exc:  # noqa: BLE001
            logging.warning(
                "RatsHandler.embed_extensions failed: %s\n%s",
                exc, traceback.format_exc(),
            )


__all__ = [
    "ATTESTATION_OID",
    "EVIDENCE_OID",
    "RATS_TOKEN_OID",
    "ExtractedEvidence",
    "ExtractedStatement",
    "RatsHandler",
]
