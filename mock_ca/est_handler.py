# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Server-side handler for the Enrollment over Secure Transport (EST) protocol.

Implements the RFC 7030 server operations on top of the existing Mock CA
building blocks: certificates are issued from PKCS#10 requests with
``certbuildutils.build_cert_from_csr`` and the responses are assembled with the
shared :mod:`resources.est_utils` message logic.

``EstHandler`` is deliberately self-contained: it only needs a CA certificate +
key (and, optionally, a certificate chain, default extensions and a state object
for tracking issued certificates). That makes it usable both from the Mock CA's
Flask app (see ``mock_ca/ca_handler.py``) and directly from unit tests.

Specifications: RFC 7030 (Sections 4.1, 4.2, 4.4, 4.5), RFC 5272, RFC 5652.
"""

import logging
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc6402, rfc9480

from resources import certbuildutils, certutils, est_utils, keyutils
from resources.exceptions import BadAsn1Data, BadRequest
from resources.typingutils import SignKey


class EstHandler:
    """Handle the EST server operations defined in RFC 7030."""

    def __init__(
        self,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: SignKey,
        ca_cert_chain: Optional[List[rfc9480.CMPCertificate]] = None,
        extensions: Optional[object] = None,
        state: Optional[object] = None,
        csr_attr_oids: Optional[List[str]] = None,
        hash_alg: str = "sha256",
        serverkeygen_key_alg: str = "rsa",
    ):
        """Initialize the EST handler.

        :param ca_cert: The issuing CA certificate.
        :param ca_key: The issuing CA private key.
        :param ca_cert_chain: The chain returned by /cacerts. Defaults to ``[ca_cert]``.
        :param extensions: Default extensions added to issued certificates (the
            Mock CA passes its prepared extensions here). Defaults to ``None``.
        :param state: Optional object exposing ``add_certs(list, was_confirmed=...)``
            used to register issued certificates with the Mock CA. Defaults to ``None``.
        :param csr_attr_oids: OIDs advertised by /csrattrs. Defaults to ``None`` (empty).
        :param hash_alg: Signature hash algorithm for issuance. Defaults to ``"sha256"``.
        :param serverkeygen_key_alg: Algorithm for server-side key generation. Defaults to ``"rsa"``.
        """
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.ca_cert_chain = ca_cert_chain or [ca_cert]
        self.extensions = extensions
        self.state = state
        self.csr_attr_oids = csr_attr_oids or []
        self.hash_alg = hash_alg
        self.serverkeygen_key_alg = serverkeygen_key_alg
        self.issued_certs: List[rfc9480.CMPCertificate] = []
        # Cache for the /cacerts response body (the CA chain is immutable).
        self._cacerts_body: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _register_issued(self, cert: rfc9480.CMPCertificate) -> None:
        """Track an issued certificate locally and in the shared state, if present."""
        self.issued_certs.append(cert)
        if self.state is not None and hasattr(self.state, "add_certs"):
            try:
                self.state.add_certs([cert], was_confirmed=True)
            except Exception as exc:  # noqa: BLE001 - state tracking is best-effort
                logging.warning("EST: could not register issued cert in state: %s", exc)

    @staticmethod
    def _decode_csr(body: bytes) -> rfc6402.CertificationRequest:
        """Base64-decode and parse a PKCS#10 request body (RFC 7030 Section 4.2.1)."""
        try:
            csr_der = est_utils.decode_est_message_body(body)
        except Exception as exc:  # noqa: BLE001
            raise BadRequest(f"EST request body is not valid base64: {exc}") from exc

        try:
            csr, _ = decoder.decode(csr_der, asn1Spec=rfc6402.CertificationRequest())
        except Exception as exc:  # noqa: BLE001
            raise BadAsn1Data(f"EST request is not a valid PKCS#10 CertificationRequest: {exc}") from exc
        return csr

    def _issue_from_csr(self, csr: rfc6402.CertificationRequest) -> rfc9480.CMPCertificate:
        """Issue a certificate from a CSR, reusing the suite's issuance logic."""
        cert = certbuildutils.build_cert_from_csr(
            csr=csr,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
            extensions=self.extensions,
            hash_alg=self.hash_alg,
        )
        self._register_issued(cert)
        return cert

    # ------------------------------------------------------------------
    # RFC 7030 Section 4.1 - /cacerts
    # ------------------------------------------------------------------

    def get_cacerts(self) -> bytes:
        """Return the /cacerts response body (base64 certs-only CMS of the CA chain).

        The body is built once and cached, since the CA chain does not change.
        """
        if self._cacerts_body is None:
            cms = est_utils.build_est_certs_only_message(self.ca_cert_chain)  # type: ignore[arg-type]
            self._cacerts_body = est_utils.encode_est_message_body(cms)
        return self._cacerts_body

    # ------------------------------------------------------------------
    # RFC 7030 Section 4.2 - /simpleenroll, /simplereenroll
    # ------------------------------------------------------------------

    def handle_enroll(self, body: bytes, reenroll: bool = False) -> bytes:
        """Process a /simpleenroll or /simplereenroll request.

        The PKCS#10 proof-of-possession signature is verified before issuance
        (RFC 7030 Section 4.2 / RFC 6402). Note: this Mock CA does not enforce the
        RFC 7030 Section 4.2.2 requirement that /simplereenroll be authenticated by
        an existing client certificate (it has no TLS client-auth context), so
        reenroll is otherwise handled like enroll.

        :param body: The base64 PKCS#10 request body.
        :param reenroll: ``True`` for /simplereenroll.
        :return: The base64 certs-only response body containing the issued cert.
        """
        csr = self._decode_csr(body)
        # Verify the CSR self-signature (proof-of-possession) before issuing.
        certutils.verify_csr_signature(csr)
        cert = self._issue_from_csr(csr)
        logging.info("EST %s issued a certificate.", "simplereenroll" if reenroll else "simpleenroll")
        return est_utils.encode_est_message_body(est_utils.build_est_certs_only_message(cert))

    # ------------------------------------------------------------------
    # RFC 7030 Section 4.4 - /serverkeygen
    # ------------------------------------------------------------------

    def handle_serverkeygen(self, body: bytes) -> Tuple[str, bytes]:
        """Process a /serverkeygen request.

        The server generates the key pair and replaces the public key in the
        client's CSR with the freshly generated one, preserving the requested
        subject and any extensions (e.g. SANs), then issues the certificate and
        returns a multipart/mixed body with the private key (PKCS#8) and the
        certificate (certs-only).

        The CSR proof-of-possession is intentionally not verified here: in
        server-side key generation the client does not hold the private key, so
        its CSR cannot carry a valid PoP for the certified key.

        :param body: The base64 PKCS#10 request body.
        :return: ``(content_type, body)`` for the multipart/mixed response.
        """
        csr = self._decode_csr(body)

        new_key = keyutils.generate_key(self.serverkeygen_key_alg)
        if not hasattr(new_key, "private_bytes"):
            raise BadRequest(
                f"Server-side key generation is not supported for key type {type(new_key)}."
            )

        # Substitute the server-generated public key into the request, keeping the
        # client's subject and extensions, then issue from it.
        csr["certificationRequestInfo"]["subjectPublicKeyInfo"] = keyutils.prepare_subject_public_key_info(new_key)
        cert = self._issue_from_csr(csr)

        key_der = new_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        logging.info("EST serverkeygen issued a certificate and generated a key.")
        return est_utils.build_est_serverkeygen_response(key_der, cert)

    # ------------------------------------------------------------------
    # RFC 7030 Section 4.5 - /csrattrs
    # ------------------------------------------------------------------

    def get_csrattrs(self) -> bytes:
        """Return the /csrattrs response body (base64 ``CsrAttrs``).

        Returns an empty body when the server advertises no attributes, which a
        client treats as "no additional attributes required".
        """
        if not self.csr_attr_oids:
            return b""
        return est_utils.encode_est_message_body(est_utils.build_est_csr_attributes(self.csr_attr_oids))
