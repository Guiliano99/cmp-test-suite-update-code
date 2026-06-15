# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Phase-3 dispatcher for RATS evidence — RA-issued nonce model.

Under the revised architecture (``constraint.md`` §9 revised, §10 added):

* The MockCA owns nonce state via :class:`mock_ca.nonce_handler.NonceHandler`.
* Each ``AttestationStatement`` in the incoming bundle is submitted to its
  RA-resolved verifier URL via
  :meth:`mock_ca.remote_att_mockca.attestation_verifier.VeraisonVerifier.submit_evidence`,
  carrying the nonce as part of the JSON body.
* The verifier becomes stateless w.r.t. freshness — it appraises one
  ``(evidence, expected_nonce, oid)`` triple per call and returns an EAR JWT.

This handler does the per-statement work:

1. Extract the ``AttestationBundle`` DER from the incoming PKIMessage.
2. Decode all statements and walk them in bundle order.
3. For each statement, compute its per-OID instance index, ask the
   :class:`NonceHandler` for the nonce + verifier URL, and submit via the
   cached :class:`VeraisonVerifier` client for that URL.
4. If any statement is rejected → raise :class:`BadMessageCheck`.
5. On success → drop the per-tx nonce state and return the first EAR JWT
   (embedded in the issued certificate as an X.509 extension).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import traceback
from dataclasses import dataclass, field
from typing import List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.x509 import load_der_x509_certificate
import cryptography.x509 as cx509
from pyasn1.codec.der import decoder as asn1_decoder
from pyasn1.codec.der import encoder as asn1_encoder
from pyasn1.type import char, namedtype, univ
from pyasn1_alt_modules import rfc9480

from mock_ca.nonce_handler import NonceHandler, ReplayError, SystemFailure
from mock_ca.remote_att_mockca.attestation_verifier import VeraisonVerifier
from resources.asn1_structures import PKIMessageTMP
from resources.cmputils import get_cert_response_from_pkimessage
from resources.convertutils import copy_asn1_certificate
from resources.remote_att_utils.csr_attest_structures import AttestationBundle
from resources.typingutils import SignKey

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# OID (id-aa-attestation) for the attestation attribute in
# certTemplate.extensions or CSR attributes.
ATTESTATION_OID = "1.2.840.113549.1.9.16.2.59"
EVIDENCE_OID = ATTESTATION_OID   # legacy alias kept for external callers
RATS_TOKEN_OID = ATTESTATION_OID  # legacy alias kept for external callers

# OID of the standard RATS Conceptual Message Wrapper (CMW) certificate
# extension, ``id-pe-cmw`` (draft-ietf-rats-msg-wrap-23 §4.4).
ID_PE_CMW_OID = "1.3.6.1.5.5.7.1.35"

# OID under which the EAR JWT is embedded as an X.509 extension on the issued
# cert.  Configurable via ``EAR_OID`` so a deployment can choose between the
# demo OID (default, raw-JWT extnValue) and the standard ``id-pe-cmw`` extension
# (CMW-wrapped extnValue).  When set to ``id-pe-cmw`` the value is a CMW JSON
# record per draft-ietf-rats-msg-wrap-23 §3; otherwise the EAR JWT bytes are
# placed verbatim (legacy behaviour, unchanged for the TPM platform flow).
EAR_EXT_OID = os.environ.get("EAR_OID", "1.7.6.5.123")


def _wrap_ear_in_cmw_json(ear_jwt: str) -> bytes:
    """Return the DER extnValue content for an ``id-pe-cmw`` EAR extension.

    Builds a CMW (Conceptual Message Wrapper) JSON *record*
    ``[media-type, base64url-nopad(message)]`` (draft-ietf-rats-msg-wrap-23 §3)
    and carries it in the CMW ``json`` (UTF8String) alternative (§4.4).  The
    value field is base64url-encoded without padding even though a JWT is
    already textual, exactly as the draft requires.

    Reuses :class:`libattest.x509.extensions.CMW` when importable (the MockCA
    ships libattest); falls back to an inline mirror of the same schema so the
    handler never fails to embed merely because that submodule is absent.
    """
    value_b64 = base64.urlsafe_b64encode(ear_jwt.encode("utf-8")).decode("ascii").rstrip("=")
    record = json.dumps(["application/eat+jwt", value_b64], separators=(",", ":"))
    try:
        from libattest.x509.extensions import CMW  # noqa: PLC0415 — canonical schema
    except Exception:  # noqa: BLE001 — libattest CMW submodule optional

        class CMW(univ.Choice):  # CMW ::= CHOICE { json UTF8String, cbor OCTET STRING }
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("json", char.UTF8String()),
                namedtype.NamedType("cbor", univ.OctetString()),
            )

    cmw = CMW()
    cmw.setComponentByName("json", char.UTF8String(record))
    return asn1_encoder.encode(cmw)


def _unwrap_context_tag(der: bytes) -> bytes:
    """Strip one outer context-specific tag from *der*, if present.

    pyasn1 components extracted from a tagged CHOICE (e.g.
    ``CertOrEncCert.certificate``) re-encode with the context tag attached.
    For an EXPLICIT tag the inner TLV is returned verbatim; for an IMPLICIT
    tag the outer tag byte is rewritten to SEQUENCE (0x30).
    """
    if not der or der[0] == 0x30:
        return der
    # Skip the outer tag + length octets.
    idx = 1
    first_len = der[idx]
    idx += 1
    if first_len & 0x80:
        idx += first_len & 0x7F
    inner = der[idx:]
    if inner and inner[0] == 0x30:
        return inner  # EXPLICIT tag: inner TLV is the full SEQUENCE
    return b"\x30" + der[1:]  # IMPLICIT tag: retag as SEQUENCE


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class ExtractedStatement:
    """One ``AttestationStatement`` decoded from an ``AttestationBundle``."""

    type_oid: str
    """Dot-form OID of the evidence type (e.g. ``2.23.133.20.1``)."""

    type_oid_der: bytes
    """DER encoding of the OBJECT IDENTIFIER — used as the ``NonceHandler`` key."""

    stmt_bytes: bytes
    """DER substrate of the statement payload (TcgAttestCertify SEQUENCE,
    or raw JWT bytes after the OCTET STRING wrapper is stripped)."""

    is_octet_string_wrapped: bool
    """``True`` when the original bundle wrapped the statement in an
    OCTET STRING (JWT case); ``False`` for direct SEQUENCE encoding (TCG)."""


@dataclass
class ExtractedEvidence:
    """All statements and bundle-level certificates for one IR.

    ``bundle_der`` is the full DER encoding of the ``AttestationBundle``
    and is what we forward to the verifier in the ``evidence`` JSON field.
    The ``statements`` list lets the dispatcher iterate without re-decoding.
    """

    bundle_der: bytes
    statements: List[ExtractedStatement]
    certs_der: List[bytes] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------


class RatsHandler:
    """Phase-3 dispatcher for RATS / CSR-attestation evidence.

    Holds:

    * ``remote_att_handler`` — a
      :class:`~mock_ca.remote_att_mockca.remote_attestation_handler.RemoteAttestationHandler`
      whose ``nonce_handler`` attribute provides per-tx nonce consumption
      and per-nonce verifier URL routing.
    * ``_clients`` — small URL → :class:`VeraisonVerifier` cache so repeat
      submissions to the same verifier reuse one HTTP client (and one
      cached EAR public key).

    Construction takes ``remote_att_handler=None`` because the MockCA
    wires the handler up after the GENM-side machinery is available
    (see ``ca_handler.py``).
    """

    def __init__(self, remote_att_handler=None):
        """Initialise the dispatcher.

        :param remote_att_handler: a ``RemoteAttestationHandler`` whose
            ``nonce_handler`` will be consulted per statement.  May be
            ``None`` at construction; assigned by the CA wiring code
            once the GENM handler exists.
        """
        self.remote_att_handler = remote_att_handler
        # url → VeraisonVerifier cache.  Keyed on the rstrip("/") form so
        # ``http://x:8444`` and ``http://x:8444/`` share one client.
        self._clients: dict[str, VeraisonVerifier] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def verify_and_get_ear(self, pki_message: PKIMessageTMP) -> Optional[str]:
        """Verify every statement in the bundle; return one EAR JWT.

        Call this BEFORE building the CMP CP response so a failure raises
        :class:`resources.exceptions.BadMessageCheck` and the outer CMP
        layer returns a rejection (no certificate issued).

        :param pki_message: The incoming CMP CR / IR / KUR / P10CR.
        :return: EAR JWT string on success; ``None`` when the request
            carries no evidence (soft skip).
        :raises BadMessageCheck:  if any statement was rejected.
        :raises SystemFailure:    if the NonceHandler cannot route an entry
            (mapped to ``PKIFailureInfo: systemFailure`` by the outer handler).
        """
        ear_jwt, _ = self._verify_bundle(pki_message)
        return ear_jwt

    def _verify_bundle(
        self, pki_message: PKIMessageTMP
    ) -> tuple[Optional[str], Optional[bytes]]:
        """Backbone of :meth:`verify_and_get_ear`.

        Returns ``(ear_jwt, None)``; the second element is kept for source
        compatibility with earlier KeyAttestPoP callers and is always
        ``None`` in the platform-only profile.  ``ear_jwt`` is ``None``
        when the request carries no evidence.
        """
        from resources.exceptions import BadMessageCheck  # noqa: PLC0415

        evidence = self.extract_evidence(pki_message)
        if evidence is None:
            logging.debug("RatsHandler: no evidence in request — skip")
            return None, None

        if (
            self.remote_att_handler is None
            or getattr(self.remote_att_handler, "nonce_handler", None) is None
        ):
            raise BadMessageCheck(
                "RatsHandler: evidence is present but no NonceHandler is "
                "configured — cannot dispatch."
            )
        nonce_handler: NonceHandler = self.remote_att_handler.nonce_handler

        tx_id = bytes(pki_message["header"]["transactionID"])

        # Two parallel counters so we can support both lookup modes:
        #
        #   per_oid_counter[oid_der]  — N-th statement *of this OID* in the
        #                               bundle.  Used when the GenM had
        #                               NonceRequest.type set per entry, so
        #                               nonces were stored under (oid, inst).
        #   total_position            — N-th statement overall in the bundle.
        #                               Used for the positional fallback when
        #                               the GenM did not set NonceRequest.type
        #                               (the freshness draft NonceRequest has no
        #                               hint field; the current gencmpclient
        #                               sets NonceRequest.type, so the (oid,
        #                               inst) keying above is normally used and
        #                               this positional fallback only applies to
        #                               legacy/typeless clients).
        per_oid_counter: dict[bytes, int] = {}
        total_position = 0

        ear_jwts: List[str] = []
        try:
            for stmt in evidence.statements:
                oid_instance = per_oid_counter.get(stmt.type_oid_der, 0)
                per_oid_counter[stmt.type_oid_der] = oid_instance + 1
                positional_instance = total_position
                total_position += 1

                # 1. Pull nonce + resolved verifier URL from the NonceHandler.
                #    Prefer the OID-keyed slot (set when GenM carried per-
                #    entry NonceRequest.type); fall through to the positional
                #    slot under None when the wire didn't carry types.
                nonce_state = self._consume_nonce(
                    nonce_handler,
                    tx_id,
                    stmt.type_oid_der,
                    oid_instance,
                    positional_instance,
                    stmt.type_oid,
                    BadMessageCheck,
                )

                # 2. (KeyAttestPoP check moved out of this loop — runs once
                #    per IR via _run_key_attest_pop_check above, since v2
                #    KeyAttestPoP no longer appears as a bundle statement.)

                # 3. Submit the bundle DER + nonce to the resolved verifier URL.
                # For TcgAttestQuote slots, also forward the TpmAttestationParams
                # DER the MockCA broadcast in NonceResponse.respInfo so the
                # verifier can check the attester quoted the requested PCR set
                # using the negotiated hash algorithm.
                pcr_selection_der = nonce_state.resp_info
                client = self._get_client(nonce_state.verifier_url)
                ear_jwt = client.submit_evidence(
                    nonce=nonce_state.nonce,
                    evidence=evidence.bundle_der,
                    evidence_oid=stmt.type_oid,
                    pcr_selection_der=pcr_selection_der,
                )
                if ear_jwt is None:
                    raise BadMessageCheck(
                        f"RatsHandler: verifier {nonce_state.verifier_url} "
                        f"rejected statement oid={stmt.type_oid} "
                        f"(oid-instance={oid_instance}, positional={positional_instance})"
                    )
                ear_jwts.append(ear_jwt)

            logging.info(
                "RatsHandler: verified %d statement(s) for tx=%s",
                len(ear_jwts), tx_id.hex(),
            )
        finally:
            # Whether the loop succeeded or raised, drop the per-tx state so
            # memory is freed and a retried IR with a new tx_id starts clean.
            nonce_handler.drop_transaction(tx_id)

        # The cert extension only carries one EAR JWT; for multi-statement
        # bundles return the first (the others have already been validated).
        # A future change could embed all of them; for now the first verdict
        # is sufficient evidence that the enrollment was attested.
        first_ear = ear_jwts[0] if ear_jwts else None
        # Platform-only profile: no KeyAttestPoP proof to surface.
        return first_ear, None

    def process_cr_attestation(
        self,
        pki_message: PKIMessageTMP,
        response: PKIMessageTMP,
        ca_key: SignKey,
    ) -> None:
        """Verify evidence and embed the EAR (+ KeyAttestPoP) extension.

        Best-effort wrapper that does not raise; failures are logged and
        the certificate is issued without an EAR extension.  Use
        :meth:`verify_and_get_ear` directly when a verifier rejection
        should fail the enrollment with a CMP error.
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
        self.embed_extensions(response, ear_jwt, ca_key)

    # ── Evidence extraction ───────────────────────────────────────────────────

    def extract_evidence(self, pki_message: PKIMessageTMP) -> Optional[ExtractedEvidence]:
        """Extract ``AttestationBundle`` from a CMP request.

        Looks in two places:

        * ``p10cr`` body → ``certificationRequestInfo.attributes``
        * ``cr`` / ``ir`` / ``kur`` body → ``certTemplate.extensions``
        """
        body_name = pki_message["body"].getName()

        if body_name == "p10cr":
            bundle_der = self._extract_from_csr_attributes(pki_message)
        elif body_name in ("cr", "ir", "kur"):
            bundle_der = self._extract_from_cert_template_extensions(pki_message)
        else:
            logging.debug("RatsHandler: unsupported body type '%s', skipping", body_name)
            return None

        if bundle_der is None:
            return None

        return self._parse_att_bundle_full(bundle_der)

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

    # ── Bundle parsing ────────────────────────────────────────────────────────

    @staticmethod
    def _parse_att_bundle_full(bundle_der: bytes) -> Optional[ExtractedEvidence]:
        """Decode an ``AttestationBundle`` into per-statement records.

        Walks every statement in the bundle (not just the first).  Each
        statement is captured along with its OID in both string and DER
        forms so :class:`NonceHandler` can be keyed without re-encoding.
        """
        try:
            bundle, _ = asn1_decoder.decode(bundle_der, asn1Spec=AttestationBundle())
        except Exception as exc:  # noqa: BLE001
            logging.warning("RatsHandler: pyasn1 parse of AttestationBundle failed: %s", exc)
            return None

        if len(bundle["attestations"]) == 0:
            logging.warning("RatsHandler: AttestationBundle has no attestations")
            return None

        statements: List[ExtractedStatement] = []
        for stmt in bundle["attestations"]:
            type_oid = str(stmt["type"])
            type_oid_der = bytes(asn1_encoder.encode(stmt["type"]))

            stmt_raw: bytes = bytes(stmt["stmt"])
            if not stmt_raw:
                logging.warning("RatsHandler: empty stmt in AttestationStatement (oid=%s)", type_oid)
                continue

            # OCTET STRING (0x04) → JWT; SEQUENCE (0x30) → TCG
            if stmt_raw[0] == 0x04:
                inner, _ = asn1_decoder.decode(stmt_raw, asn1Spec=univ.OctetString())
                stmt_bytes = bytes(inner)
                is_wrapped = True
            else:
                stmt_bytes = stmt_raw
                is_wrapped = False

            statements.append(
                ExtractedStatement(
                    type_oid=type_oid,
                    type_oid_der=type_oid_der,
                    stmt_bytes=stmt_bytes,
                    is_octet_string_wrapped=is_wrapped,
                )
            )

        certs_der: List[bytes] = []
        if bundle["certs"].isValue:
            for cert_choice in bundle["certs"]:
                if cert_choice.getName() == "certificate":
                    certs_der.append(asn1_encoder.encode(cert_choice["certificate"]))

        logging.info(
            "RatsHandler: parsed bundle — %d statement(s), %d cert(s)",
            len(statements), len(certs_der),
        )
        return ExtractedEvidence(
            bundle_der=bundle_der,
            statements=statements,
            certs_der=certs_der,
        )

    # ── Nonce consume helper (OID → positional fallback) ─────────────────────

    @staticmethod
    def _consume_nonce(
        nonce_handler: "NonceHandler",
        tx_id: bytes,
        oid_der: bytes,
        oid_instance: int,
        positional_instance: int,
        oid_dot: str,
        BadMessageCheck,  # injected to avoid the import cycle on the inner-class side
    ):
        """Try OID-keyed consume first; fall back to positional (None-keyed).

        The bundle's ``AttestationStatement.type`` always carries an OID, but
        the GenM's ``NonceRequest.type`` field is optional and the current
        gencmpclient does NOT set it.  When that's the case the issued nonce
        is filed under ``(None, position)`` rather than ``(oid_der, instance)``.

        This helper:
          1. Tries the OID-keyed slot (the future-proof path: works when the
             attester sets NonceRequest.type to match the AttestationStatement OID).
          2. On KeyError, falls back to ``(None, positional_instance)`` —
             today's wire reality.  Other exceptions (expired, replay) come
             through unchanged because they are real errors regardless of mode.

        :raises BadMessageCheck: on any final lookup failure.
        """
        try:
            return nonce_handler.consume(
                tx_id=tx_id,
                evidence_oid_der=oid_der,
                instance=oid_instance,
            )
        except KeyError:
            # Fall through to positional lookup below.
            pass
        except ValueError as exc:
            raise BadMessageCheck(
                f"RatsHandler: nonce expired for oid={oid_dot} "
                f"instance={oid_instance}: {exc}"
            ) from exc
        except ReplayError as exc:
            raise BadMessageCheck(
                f"RatsHandler: nonce already consumed (replay) for "
                f"oid={oid_dot} instance={oid_instance}: {exc}"
            ) from exc

        try:
            state = nonce_handler.consume(
                tx_id=tx_id,
                evidence_oid_der=None,
                instance=positional_instance,
            )
            logging.debug(
                "RatsHandler: positional fallback consume(None, %d) hit for oid=%s",
                positional_instance, oid_dot,
            )
            return state
        except KeyError as exc:
            raise BadMessageCheck(
                f"RatsHandler: no nonce for evidence statement "
                f"oid={oid_dot} (oid-instance={oid_instance}, "
                f"positional={positional_instance}): {exc}"
            ) from exc
        except ValueError as exc:
            raise BadMessageCheck(
                f"RatsHandler: nonce expired (positional={positional_instance}): {exc}"
            ) from exc
        except ReplayError as exc:
            raise BadMessageCheck(
                f"RatsHandler: nonce already consumed (positional={positional_instance}): {exc}"
            ) from exc

    # ── Verifier-client cache ─────────────────────────────────────────────────

    def _get_client(self, verifier_url: str) -> VeraisonVerifier:
        """Return (creating if needed) the VeraisonVerifier for *verifier_url*.

        Caching is per-URL — repeat submissions inside one enrollment reuse
        the same client and therefore the same cached EAR public key.
        """
        normalized = verifier_url.rstrip("/")
        client = self._clients.get(normalized)
        if client is None:
            client = VeraisonVerifier(base_url=normalized)
            self._clients[normalized] = client
            logging.debug("RatsHandler: created VeraisonVerifier client for %s", normalized)
        return client

    # ── Cert extension embedding ─────────────────────────────────────────────

    @classmethod
    def embed_ear_extension(
        cls,
        response: PKIMessageTMP,
        ear_jwt: str,
        ca_key: SignKey,
    ) -> None:
        """Backward-compatible shim — embed only the EAR JWT extension.

        Equivalent to :meth:`embed_extensions` with ``pop_proof_der=None``;
        kept so external callers (and the legacy non-PoP enrollment path)
        continue to compile.
        """
        cls.embed_extensions(response, ear_jwt, ca_key, pop_proof_der=None)

    @staticmethod
    def embed_extensions(
        response: PKIMessageTMP,
        ear_jwt: str,
        ca_key: SignKey,
        *,
        pop_proof_der: Optional[bytes] = None,
    ) -> None:
        """Add the EAR JWT (and optionally the KeyAttestPoP proof) extensions.

        The certificate is extracted from the CP response, rebuilt with the
        new extension(s) using the ``cryptography`` library, re-signed with
        *ca_key*, and copied back into the response in place.

        :param response: the CMP CP response containing the issued cert.
        :param ear_jwt: the compact-serialised EAR JWT string.
        :param ca_key: CA private key used to re-sign the rebuilt cert.
        :param pop_proof_der: when supplied, the DER bytes of the
            ``KeyAttestPoPProof`` from the CSR are copied verbatim onto
            the issued cert as an X.509 v3 extension under
            :func:`resolve_key_attest_pop_oid` (SPEC §DR-8).  ``None``
            for non-PoP enrollments.
        """
        try:
            cert_resp = get_cert_response_from_pkimessage(response, response_index=0)
            cert_choice = cert_resp["certifiedKeyPair"]["certOrEncCert"]["certificate"]

            # Re-encode the existing certificate, add the extensions, re-sign.
            # cert_choice carries CertOrEncCert's context tag from the CHOICE;
            # unwrap it so the DER is a plain Certificate TLV.
            cmp_cert_der = _unwrap_context_tag(asn1_encoder.encode(cert_choice))
            x509_cert = load_der_x509_certificate(cmp_cert_der)

            existing_extensions = list(x509_cert.extensions)

            ear_oid = cx509.ObjectIdentifier(EAR_EXT_OID)
            if EAR_EXT_OID == ID_PE_CMW_OID:
                # Standard RATS CMW extension: extnValue is a CMW JSON record
                # wrapping the EAR JWT (draft-ietf-rats-msg-wrap-23 §4.4).
                ear_value = _wrap_ear_in_cmw_json(ear_jwt)
            else:
                # Legacy/demo OID: EAR JWT bytes placed verbatim.
                ear_value = ear_jwt.encode("utf-8")
            existing_extensions.append(cx509.Extension(
                oid=ear_oid,
                critical=False,
                value=cx509.UnrecognizedExtension(ear_oid, ear_value),
            ))

            if pop_proof_der is not None:
                # Lazy import: only the dormant KeyAttestPoP path needs it
                # (the platform-only libattest tree may not ship the module).
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

            # Copy the rebuilt cert back into the CMP response in place.
            new_cmp_cert, _ = asn1_decoder.decode(
                rebuilt.public_bytes(serialization.Encoding.DER),
                asn1Spec=rfc9480.CMPCertificate(),
            )
            copy_asn1_certificate(new_cmp_cert, cert_choice)
            embedded = [EAR_EXT_OID]
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
