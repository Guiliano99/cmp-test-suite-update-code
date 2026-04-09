# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Handler for RATS (Remote ATtestation procedureS) token extraction and verification.

RatsHandler extracts an attestation token from an incoming CMP CR, submits it
to the configured verifier, and embeds the resulting EAR (Entity Attestation
Result) JWT as an X.509 extension in the issued certificate.
"""

import base64
import json
import logging
from typing import Optional

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
from resources.typingutils import SignKey

# OID for the RATS attestation token carried in the CSR extensions
RATS_TOKEN_OID = "1.2.840.113549.1.9.16.2.59"
# OID for the Veraison EAR JWT extension embedded in the issued certificate
EAR_EXT_OID = "1.7.6.5.123"


class RatsHandler:
    """Handles RATS attestation token extraction, verification, and EAR embedding.

    Typical usage inside a CMP CR handler::

        rats_handler = RatsHandler(remote_att_handler)
        rats_handler.process_cr_attestation(pki_message, response, ca_key)

    The handler is a no-op when ``remote_att_handler`` is ``None``.
    """

    def __init__(self, remote_att_handler=None):
        """Initialise the handler.

        :param remote_att_handler: A :class:`~mock_ca.remote_attestation_handler.RemoteAttestationHandler`
                                   instance that provides :meth:`verify_token`.  May be ``None``; in
                                   that case all operations are skipped.
        """
        self.remote_att_handler = remote_att_handler

    # ── Public API ────────────────────────────────────────────────────────────

    def process_cr_attestation(
        self,
        pki_message: PKIMessageTMP,
        response: PKIMessageTMP,
        ca_key: SignKey,
    ) -> None:
        """Extract the RATS token from *pki_message*, verify it, and embed the EAR.

        Logs a warning if any step fails but does not raise — the certificate is
        still issued, just without the EAR extension.

        :param pki_message: The incoming CMP CR PKIMessage.
        :param response: The outgoing CMP CP PKIMessage (modified in-place).
        :param ca_key: The CA private key used to re-sign the certificate after
                       the EAR extension is added.
        """
        if self.remote_att_handler is None:
            logging.debug("RatsHandler: no remote_att_handler configured, skipping")
            return

        token = self.extract_token(pki_message)
        if not token:
            logging.debug("RatsHandler: no RATS token found in CR")
            return

        logging.info("RatsHandler: found RATS token (%d bytes)", len(token))
        nonce = self.extract_nonce_from_token(token)
        ear_jwt = self.remote_att_handler.verify_token(
            token,
            media_type="application/eat-jwt",
            nonce=nonce,
        )
        if not ear_jwt:
            logging.warning("RatsHandler: token verification failed; EAR will not be embedded")
            return

        self.embed_ear_extension(response, ear_jwt, ca_key)

    def extract_token(self, pki_message: PKIMessageTMP) -> Optional[bytes]:
        """Extract the RATS attestation token from the CR's certTemplate extensions.

        Searches for OID ``1.2.840.113549.1.9.16.2.59`` in the extensions of the
        first certification request body.

        :return: Raw token bytes, or ``None`` if the extension is absent.
        """
        try:
            cert_req = pki_message["body"]["cr"][0]["certReq"]
            extensions = cert_req["certTemplate"]["extensions"]
            logging.info("RatsHandler: certTemplate has %d extensions", len(extensions))
            for ext in extensions:
                oid = str(ext["extnID"])
                logging.info("RatsHandler: found extension OID: %s", oid)
                if oid == RATS_TOKEN_OID:
                    extn_value = bytes(ext["extnValue"])
                    token_bytes = RatsHandler._parse_att_bundle_der(extn_value)
                    if token_bytes:
                        logging.info("RatsHandler: extracted token (%d bytes)", len(token_bytes))
                        return token_bytes
                    logging.warning("RatsHandler: _parse_att_bundle_der returned None")
        except Exception as exc:
            logging.warning("RatsHandler: could not extract RATS token: %s", exc)
        return None

    @staticmethod
    def _parse_att_bundle_der(der: bytes) -> Optional[bytes]:
        """Extract the OCTET STRING token from a DER-encoded LOCAL_ATT_BUNDLE.

        Walks the fixed DER structure without relying on pyasn1 schema:
          SEQUENCE {                   <- AttestationBundle (outer)
            SEQUENCE {               <- attestations SEQUENCE OF
              SEQUENCE {             <- first AttestationStatement
                OID                  <- token type
                OCTET STRING         <- the actual token bytes
              }
            }
          }

        :return: Raw token bytes, or None if the structure is unexpected.
        """
        def _read_length(data: bytes, pos: int):
            if data[pos] & 0x80:
                n = data[pos] & 0x7F
                length = int.from_bytes(data[pos + 1: pos + 1 + n], "big")
                return length, pos + 1 + n
            return data[pos], pos + 1

        try:
            pos = 0
            # Level 1: outer SEQUENCE (AttestationBundle)
            if der[pos] != 0x30:
                return None
            pos += 1
            _, pos = _read_length(der, pos)
            # Level 2: attestations SEQUENCE OF (wraps AttestationStatements)
            if der[pos] != 0x30:
                return None
            pos += 1
            _, pos = _read_length(der, pos)
            # Level 3: first AttestationStatement SEQUENCE { OID, OCTET STRING }
            if der[pos] != 0x30:
                return None
            pos += 1
            _, pos = _read_length(der, pos)
            # OID (type) — skip it
            if der[pos] != 0x06:
                return None
            pos += 1
            oid_len, pos = _read_length(der, pos)
            pos += oid_len
            # OCTET STRING (stmt — the actual token bytes)
            if der[pos] != 0x04:
                return None
            pos += 1
            token_len, pos = _read_length(der, pos)
            return der[pos: pos + token_len]
        except Exception as exc:
            logging.warning("RatsHandler: DER parse of att bundle failed: %s", exc)
            return None

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
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + b"=" * padding))
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
        extension using the ``cryptography`` library, re-signed with *ca_key*, and
        written back into *response* in-place.

        :param response: CMP CP PKIMessage to modify.
        :param ear_jwt: EAR JWT string returned by the verifier.
        :param ca_key: CA private key for re-signing.
        """
        try:
            cert_der = bytes(
                response["body"]["cp"][0]["certifiedKeyPair"]["certOrEncCert"]["certificate"]
            )
            cert = load_der_x509_certificate(cert_der)

            ear_oid = cx509.ObjectIdentifier(EAR_EXT_OID)
            # Wrap the JWT bytes in a DER OCTET STRING so the extension value is
            # well-formed ASN.1 (extnValue is itself an OCTET STRING whose content
            # is the DER encoding of the extension's actual value).
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
            response["body"]["cp"][0]["certifiedKeyPair"]["certOrEncCert"]["certificate"] = new_cert_asn1
            logging.info("RatsHandler: embedded EAR JWT extension (OID %s)", EAR_EXT_OID)
        except Exception as exc:
            logging.error("RatsHandler: failed to embed EAR extension: %s", exc)
