# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Handler for RATS (Remote ATtestation procedureS) token extraction and verification.

RatsHandler extracts an attestation token from an incoming CMP CR or P10CR,
submits it to the configured verifier, and embeds the resulting EAR (Entity
Attestation Result) JWT as an X.509 extension in the issued certificate.

Evidence location
-----------------
Evidence is carried in an ``AttestationBundle`` under OID ``1.2.840.113549.1.9.16.2.59``
(``id-aa-evidence``).  The bundle may appear in two places depending on the CMP
body type:

* **CertTemplate extensions** – used by ``cr`` and ``ir`` body types.  The OID
  appears in ``CertReqMessages[0].certReq.certTemplate.extensions``.
* **CSR attributes** – used by ``p10cr`` body type.  The OID appears in
  ``CertificationRequestInfo.attributes``.

Both locations are transparently supported; the extraction is transparent to
the downstream verifier path.

Evidence type dispatch
-----------------------
The first ``AttestationStatement`` inside the bundle carries a ``type`` OID
that identifies the evidence format:

* Any OID other than ``2.23.133.20.1`` → JWT / RATS path (``remote_att_handler``).
* ``2.23.133.20.1`` (``id-tcg-attest-certify``) → TPM path (``tpm_att_handler``).
"""

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
from pyasn1.type import univ
from pyasn1_alt_modules import rfc9480

from resources.asn1_structures import PKIMessageTMP
from resources.cmputils import get_cert_response_from_pkimessage
from resources.convertutils import copy_asn1_certificate
from resources.remote_att_utils.csr_attest_structures import AttestationBundle
from resources.typingutils import SignKey

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# OID for the evidence attribute in certTemplate.extensions or CSR attributes
# draft-ietf-lamps-csr-attestation / id-aa-evidence
EVIDENCE_OID = "1.2.840.113549.1.9.16.2.59"
# Legacy alias kept for external callers
RATS_TOKEN_OID = EVIDENCE_OID

# OID for the Veraison EAR JWT extension embedded in the issued certificate
EAR_EXT_OID = "1.7.6.5.123"

# Evidence type OIDs (AttestationStatement.type)
# id-tcg-attest-certify — TCG CSR Attestation (TcgAttestCertify SEQUENCE)
TPM_CERTIFY_OID = "2.23.133.20.1"


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class ExtractedEvidence:
    """Evidence extracted from a CMP request.

    Carries the full ``AttestationBundle`` DER plus pre-parsed fields so the
    caller can dispatch to the right verifier without re-parsing.

    Attributes:
        bundle_der: Full DER encoding of the ``AttestationBundle``.
        type_oid:   OID string from the first ``AttestationStatement.type``
                    field.  Used to select the verifier back-end.
        stmt_bytes: Payload of the first attestation statement.  For JWT/RATS
                    evidence this is the raw JWT bytes (the OCTET STRING
                    wrapper has been stripped).  For TCG evidence this is the
                    full DER of the ``TcgAttestCertify`` SEQUENCE (tag
                    included).
        is_octet_string_wrapped: ``True`` when the original ``stmt`` field was
                    an OCTET STRING (JWT case); ``False`` when it was a
                    directly-encoded SEQUENCE (TCG case).
        certs_der:  DER-encoded certificates from the ``certs`` field of the
                    bundle, e.g. the AK certificate chain for TPM attestation.
    """

    bundle_der: bytes
    type_oid: str
    stmt_bytes: bytes
    is_octet_string_wrapped: bool
    certs_der: List[bytes] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------


class RatsHandler:
    """Handles RATS / CSR-attestation token extraction, verification, and EAR embedding.

    Typical usage inside a CMP CR handler::

        rats_handler = RatsHandler(remote_att_handler=jwt_verifier)
        rats_handler.process_cr_attestation(pki_message, response, ca_key)

    The handler is a no-op when both verifier references are ``None``.

    The ``remote_att_handler`` is used for JWT / RATS evidence (any type OID
    other than the TCG certify OID).  The ``tpm_att_handler`` is used for
    ``TcgAttestCertify`` evidence.  Either may be ``None``; when the
    corresponding verifier is absent the evidence type is still extracted and
    logged, but no EAR is embedded.
    """

    def __init__(self, remote_att_handler=None, tpm_att_handler=None):
        """Initialise the handler.

        :param remote_att_handler: Verifier for JWT / RATS evidence.  Provides
            ``verify_token(token_bytes, media_type, nonce)`` and
            ``get_nonce(size)``.  May be ``None``.
        :param tpm_att_handler: Verifier for TPM ``TcgAttestCertify`` evidence.
            Provides ``verify_token(bundle_der, media_type, nonce)``.
            May be ``None``; if ``None`` the handler will try to create one
            lazily from the ``VERIFIER_NONCE_URL_TPM`` environment variable.
        """
        self.remote_att_handler = remote_att_handler
        self.tpm_att_handler = tpm_att_handler

    # ── Public API ────────────────────────────────────────────────────────────

    def process_cr_attestation(
        self,
        pki_message: PKIMessageTMP,
        response: PKIMessageTMP,
        ca_key: SignKey,
    ) -> None:
        """Extract evidence from *pki_message*, verify it, and embed the EAR.

        Dispatches to ``remote_att_handler`` for JWT evidence or
        ``tpm_att_handler`` for TPM evidence.  Logs a warning if any step
        fails but does not raise — the certificate is still issued, just
        without the EAR extension.

        :param pki_message: The incoming CMP request (``cr``, ``ir``, or
            ``p10cr`` body).
        :param response: The outgoing CMP CP PKIMessage (modified in-place).
        :param ca_key: The CA private key used to re-sign the certificate after
            the EAR extension is added.
        """
        evidence = self.extract_evidence(pki_message)
        if evidence is None:
            logging.debug("RatsHandler: no evidence found in request")
            return

        logging.info(
            "RatsHandler: found evidence (type=%s, bundle=%d bytes)",
            evidence.type_oid,
            len(evidence.bundle_der),
        )

        ear_jwt: Optional[str] = None

        if evidence.type_oid == TPM_CERTIFY_OID:
            ear_jwt = self._verify_tpm_evidence(evidence)
        else:
            ear_jwt = self._verify_jwt_evidence(evidence)

        if not ear_jwt:
            logging.warning("RatsHandler: verification failed; EAR will not be embedded")
            return

        self.embed_ear_extension(response, ear_jwt, ca_key)

    # ── Evidence extraction ───────────────────────────────────────────────────

    def extract_evidence(self, pki_message: PKIMessageTMP) -> Optional[ExtractedEvidence]:
        """Extract ``AttestationBundle`` from a CMP request.

        Checks two locations:

        * ``p10cr`` body → ``certificationRequestInfo.attributes``
        * ``cr`` / ``ir`` / ``kur`` body → ``certTemplate.extensions``

        :return: Parsed :class:`ExtractedEvidence`, or ``None`` if the OID is
            absent or parsing fails.
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

    def extract_token(self, pki_message: PKIMessageTMP) -> Optional[bytes]:
        """Extract the raw RATS token bytes.

        Deprecated compatibility wrapper around :meth:`extract_evidence`.
        Returns only the ``stmt_bytes`` of the first attestation statement.
        Use :meth:`extract_evidence` for new code.

        :return: Raw token bytes (JWT for RATS; DER for TCG), or ``None``.
        """
        evidence = self.extract_evidence(pki_message)
        return evidence.stmt_bytes if evidence else None

    @staticmethod
    def _extract_from_cert_template_extensions(pki_message: PKIMessageTMP) -> Optional[bytes]:
        """Return ``AttestationBundle`` DER from ``certTemplate.extensions``.

        Searches the extensions of the first ``CertReqMessages`` entry for OID
        ``1.2.840.113549.1.9.16.2.59`` (``id-aa-evidence``).

        :return: Raw DER of the ``AttestationBundle``, or ``None``.
        """
        try:
            body_name = pki_message["body"].getName()
            cert_req = pki_message["body"][body_name][0]["certReq"]
            extensions = cert_req["certTemplate"]["extensions"]
            if not extensions.isValue:
                return None
            for ext in extensions:
                if str(ext["extnID"]) == EVIDENCE_OID:
                    # extnValue is OCTET STRING whose content is AttestationBundle DER
                    bundle_der = bytes(ext["extnValue"])
                    logging.info(
                        "RatsHandler: found evidence in certTemplate.extensions (%d bytes)",
                        len(bundle_der),
                    )
                    return bundle_der
        except Exception as exc:
            logging.warning(
                "RatsHandler: failed to extract from certTemplate.extensions: %s", exc
            )
        return None

    @staticmethod
    def _extract_from_csr_attributes(pki_message: PKIMessageTMP) -> Optional[bytes]:
        """Return ``AttestationBundle`` DER from PKCS#10 CSR attributes.

        Searches ``certificationRequestInfo.attributes`` for OID
        ``1.2.840.113549.1.9.16.2.59`` (``id-aa-evidence``) and returns the
        raw DER of the first attribute value.

        :return: Raw DER of the ``AttestationBundle``, or ``None``.
        """
        try:
            csr = pki_message["body"]["p10cr"]
            cri = csr["certificationRequestInfo"]
            if not cri["attributes"].isValue:
                return None
            for attr in cri["attributes"]:
                if str(attr["attrType"]) == EVIDENCE_OID:
                    values = attr["attrValues"]
                    if len(values) == 0:
                        continue
                    # attrValues[0] is univ.Any; .asOctets() returns the raw DER
                    bundle_der = values[0].asOctets()
                    logging.info(
                        "RatsHandler: found evidence in CSR attributes (%d bytes)",
                        len(bundle_der),
                    )
                    return bundle_der
        except Exception as exc:
            logging.warning(
                "RatsHandler: failed to extract from CSR attributes: %s", exc
            )
        return None

    # ── Bundle parsing ────────────────────────────────────────────────────────

    @staticmethod
    def _parse_att_bundle_full(bundle_der: bytes) -> Optional[ExtractedEvidence]:
        """Parse an ``AttestationBundle`` DER into an :class:`ExtractedEvidence`.

        Decodes the bundle with pyasn1 to identify the evidence type OID and
        extract the statement payload.

        For **OCTET STRING** statements (JWT / RATS): the wrapper is stripped
        and ``stmt_bytes`` contains the raw JWT bytes.

        For **SEQUENCE** statements (TCG ``TcgAttestCertify``): the full DER
        including the SEQUENCE tag is preserved in ``stmt_bytes``.

        Falls back to the legacy raw-DER walk on pyasn1 decode failure so that
        existing JWT-based tests are not broken by a minor schema mismatch.

        :return: :class:`ExtractedEvidence`, or ``None`` on total failure.
        """
        try:
            bundle, _ = asn1_decoder.decode(bundle_der, asn1Spec=AttestationBundle())

            if len(bundle["attestations"]) == 0:
                logging.warning("RatsHandler: AttestationBundle has no attestations")
                return None

            first_stmt = bundle["attestations"][0]
            type_oid = str(first_stmt["type"])

            # stmt is univ.Any — raw substrate bytes including the outer ASN.1 tag
            stmt_raw: bytes = bytes(first_stmt["stmt"])

            if not stmt_raw:
                logging.warning("RatsHandler: empty stmt in AttestationStatement")
                return None

            # Determine encoding: OCTET STRING (0x04) → JWT; SEQUENCE (0x30) → TCG
            if stmt_raw[0] == 0x04:
                inner, _ = asn1_decoder.decode(stmt_raw, asn1Spec=univ.OctetString())
                stmt_bytes = bytes(inner)
                is_wrapped = True
            else:
                # Structured type (e.g., TcgAttestCertify SEQUENCE)
                stmt_bytes = stmt_raw
                is_wrapped = False

            # Extract certificate chain from optional certs field
            certs_der: List[bytes] = []
            if bundle["certs"].isValue:
                for cert_choice in bundle["certs"]:
                    name = cert_choice.getName()
                    if name == "certificate":
                        certs_der.append(asn1_encoder.encode(cert_choice["certificate"]))

            logging.info(
                "RatsHandler: parsed bundle — type=%s, stmt=%d bytes, certs=%d",
                type_oid,
                len(stmt_bytes),
                len(certs_der),
            )
            return ExtractedEvidence(
                bundle_der=bundle_der,
                type_oid=type_oid,
                stmt_bytes=stmt_bytes,
                is_octet_string_wrapped=is_wrapped,
                certs_der=certs_der,
            )

        except Exception as exc:
            logging.warning(
                "RatsHandler: pyasn1 parse of AttestationBundle failed: %s; "
                "falling back to raw-DER walk",
                exc,
            )

        # Legacy fallback: raw DER walk (handles JWT-only bundles)
        token = RatsHandler._parse_att_bundle_der(bundle_der)
        if token:
            logging.info("RatsHandler: legacy DER walk succeeded (%d bytes)", len(token))
            return ExtractedEvidence(
                bundle_der=bundle_der,
                type_oid=EVIDENCE_OID,  # type unknown, assume RATS/JWT
                stmt_bytes=token,
                is_octet_string_wrapped=True,
                certs_der=[],
            )
        return None

    @staticmethod
    def _parse_att_bundle_der(der: bytes) -> Optional[bytes]:
        """Extract the OCTET STRING token from a DER-encoded ``AttestationBundle``.

        Legacy raw-DER walk for JWT bundles.  Walks the fixed structure::

            SEQUENCE {               ← AttestationBundle
              SEQUENCE {             ← attestations SEQUENCE OF
                SEQUENCE {           ← first AttestationStatement
                  OID                ← type
                  OCTET STRING       ← stmt (JWT bytes)
                }
              }
            }

        :return: Raw JWT bytes, or ``None`` if the structure is unexpected.
        """

        def _read_length(data: bytes, pos: int):
            if data[pos] & 0x80:
                n = data[pos] & 0x7F
                length = int.from_bytes(data[pos + 1 : pos + 1 + n], "big")
                return length, pos + 1 + n
            return data[pos], pos + 1

        try:
            pos = 0
            if der[pos] != 0x30:
                return None
            pos += 1
            _, pos = _read_length(der, pos)
            if der[pos] != 0x30:
                return None
            pos += 1
            _, pos = _read_length(der, pos)
            if der[pos] != 0x30:
                return None
            pos += 1
            _, pos = _read_length(der, pos)
            if der[pos] != 0x06:
                return None
            pos += 1
            oid_len, pos = _read_length(der, pos)
            pos += oid_len
            if der[pos] != 0x04:
                return None
            pos += 1
            token_len, pos = _read_length(der, pos)
            return der[pos : pos + token_len]
        except Exception as exc:
            logging.warning("RatsHandler: legacy DER walk failed: %s", exc)
            return None

    # ── Verifier dispatch ─────────────────────────────────────────────────────

    def _verify_jwt_evidence(self, evidence: ExtractedEvidence) -> Optional[str]:
        """Verify JWT / RATS evidence with ``remote_att_handler``.

        :return: EAR JWT string, or ``None`` on failure.
        """
        if self.remote_att_handler is None:
            logging.debug("RatsHandler: no remote_att_handler configured, skipping JWT verification")
            return None

        token = evidence.stmt_bytes
        nonce = self.extract_nonce_from_token(token)
        logging.info("RatsHandler: submitting JWT token (%d bytes) to remote verifier", len(token))
        return self.remote_att_handler.verify_token(
            token,
            media_type="application/eat-jwt",
            nonce=nonce,
        )

    def _verify_tpm_evidence(self, evidence: ExtractedEvidence) -> Optional[str]:
        """Verify TPM ``TcgAttestCertify`` evidence with ``tpm_att_handler``.

        If ``tpm_att_handler`` is ``None``, attempts lazy creation from the
        ``VERIFIER_NONCE_URL_TPM`` environment variable.

        :return: EAR JWT string, or ``None`` on failure.
        """
        handler = self._get_tpm_att_handler()
        if handler is None:
            logging.warning(
                "RatsHandler: TPM evidence (type=%s) found but no tpm_att_handler "
                "configured and VERIFIER_NONCE_URL_TPM is not set",
                evidence.type_oid,
            )
            return None

        logging.info(
            "RatsHandler: submitting TPM evidence bundle (%d bytes) to TPM verifier",
            len(evidence.bundle_der),
        )
        return handler.verify_token(
            evidence.bundle_der,
            media_type="application/vnd.tcg.attest-certify",
            nonce=None,  # nonce is embedded in TPMS_ATTEST.qualifyingData
        )

    def _get_tpm_att_handler(self):
        """Return ``tpm_att_handler``, creating it lazily from env var if needed."""
        if self.tpm_att_handler is not None:
            return self.tpm_att_handler

        tpm_url = os.environ.get("VERIFIER_NONCE_URL_TPM", "").strip()
        if not tpm_url:
            return None

        # Lazy import to avoid circular dependency at module load time
        from mock_ca.attestation_verifier import VeraisonVerifier  # noqa: PLC0415

        logging.info("RatsHandler: lazily creating TPM verifier from VERIFIER_NONCE_URL_TPM=%s", tpm_url)
        self.tpm_att_handler = VeraisonVerifier(base_url=tpm_url, fetch_timeout=10)
        return self.tpm_att_handler

    # ── Nonce / EAR helpers ───────────────────────────────────────────────────

    @staticmethod
    def extract_nonce_from_token(token_bytes: bytes) -> Optional[bytes]:
        """Decode the JWT payload and return the ``eat_nonce`` as raw bytes.

        :return: Nonce bytes, or ``None`` if the token is not a JWT or has no nonce.
        """
        try:
            parts = token_bytes.split(b".")
            if len(parts) < 2:
                return None
            payload_b64 = parts[1]
            padding = (4 - len(payload_b64) % 4) % 4
            payload = json.loads(
                base64.urlsafe_b64decode(payload_b64 + b"=" * padding)
            )
            nonce_val = payload.get("eat_nonce")
            if nonce_val is None:
                return None
            if isinstance(nonce_val, str):
                return base64.urlsafe_b64decode(nonce_val + "==")
            return bytes(nonce_val)
        except Exception as exc:
            logging.debug("RatsHandler: could not extract nonce from token: %s", exc)
        return None

    @staticmethod
    def embed_ear_extension(
        response: PKIMessageTMP,
        ear_jwt: str,
        ca_key: SignKey,
    ) -> None:
        """Add the EAR JWT as OID ``1.7.6.5.123`` OctetString to the issued certificate.

        The certificate is extracted from the CP response, rebuilt with the new
        extension using the ``cryptography`` library, re-signed with *ca_key*,
        and written back into *response* in-place.

        :param response: CMP CP PKIMessage to modify.
        :param ear_jwt: EAR JWT string returned by the verifier.
        :param ca_key: CA private key for re-signing.
        """
        try:
            cert_response = get_cert_response_from_pkimessage(response, response_index=0)
            cert_asn1 = cert_response["certifiedKeyPair"]["certOrEncCert"]["certificate"]
            cert_asn1_untagged = copy_asn1_certificate(cert_asn1)
            cert_der = asn1_encoder.encode(cert_asn1_untagged)
            cert = load_der_x509_certificate(cert_der)

            ear_oid = cx509.ObjectIdentifier(EAR_EXT_OID)
            ear_value = asn1_encoder.encode(univ.OctetString(ear_jwt.encode()))

            builder = cx509.CertificateBuilder(
                subject_name=cert.subject,
                issuer_name=cert.issuer,
                public_key=cert.public_key(),
                serial_number=cert.serial_number,
                not_valid_before=cert.not_valid_before_utc,
                not_valid_after=cert.not_valid_after_utc,
            )
            for ext in cert.extensions:
                builder = builder.add_extension(ext.value, critical=ext.critical)
            builder = builder.add_extension(
                cx509.UnrecognizedExtension(ear_oid, ear_value),
                critical=False,
            )

            ca_key_der = ca_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            crypto_ca_key = load_der_private_key(ca_key_der, password=None)

            if isinstance(crypto_ca_key, Ed25519PrivateKey):
                new_cert = builder.sign(crypto_ca_key, algorithm=None)
            else:
                new_cert = builder.sign(crypto_ca_key, algorithm=hashes.SHA256())

            new_cert_asn1, _ = asn1_decoder.decode(
                new_cert.public_bytes(serialization.Encoding.DER),
                asn1Spec=rfc9480.CMPCertificate(),
            )
            copy_asn1_certificate(new_cert_asn1, target=cert_asn1)
            logging.info("RatsHandler: embedded EAR JWT extension (OID %s)", EAR_EXT_OID)
        except Exception as exc:
            logging.error(
                "RatsHandler: failed to embed EAR extension: %s\n%s",
                exc,
                traceback.format_exc(),
            )
