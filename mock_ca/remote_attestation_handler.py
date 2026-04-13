# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Remote attestation handler for CMP MockCA.

This module implements remote attestation functionality for the CMP MockCA test server,
supporting nonce freshness mechanisms and attestation evidence processing as defined in:
- draft-ietf-lamps-attestation-freshness: Nonce-based freshness for attestation
- draft-ietf-lamps-csr-attestation: CSR attestation evidence attributes

The RemoteAttestationHandler manages nonce generation, validation of nonce requests,
and processing of attestation evidence in certification requests.

For the Veraison-specific implementation used in the demonstration environment see
``mock_ca.remote_att_mockca.RemoteAttestationHandler``.
"""

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc6402, rfc9480

from mock_ca.attestation_verifier import AttestationVerifier
from mock_ca.db_config_vars import RemoteAttestationConfig
from pq_logic.tmp_oids import id_it_nonceResponse
from resources.certextractutils import csr_contains_attribute
from resources.exceptions import RemoteAttestationError
from resources.remote_att_utils.attest_nonce_freshness_structures import (
    NonceRequestASN1,
    NonceRequestValueASN1,
    NonceResponseValueASN1,
)
from resources.remote_att_utils.csr_attest_structures import AttestationBundle, id_aa_attestation
from resources.remote_attestation_utils import (
    get_attestation_evidence_attribute,
    prepare_nonce_response_from_request,
    validate_nonce_request,
)
from resources.utils import fetch_value_from_location

# TODO specify whether the txID can be new or must be the same.


@dataclass
class NonceVerifierEntry:
    """Entry for a remote attestation verifier.

    Attributes:
        - tx_id: The transaction ID of the CMP message associated with this nonce.
        - nonce: The nonce value that was issued to the client.
        - created_time: The timestamp when the nonce was issued, used for expiration checks.
        - evidence_type: The OID identifying the type of attestation evidence
          this nonce is associated with (e.g., PSA, CCA), if any.

    """

    tx_id: bytes
    nonce: bytes
    created_time: datetime
    evidence_type: Optional[univ.ObjectIdentifier]


class RemoteAttestationHandler:
    """Handler for remote attestation and nonce freshness in CMP protocol.

    This is the base implementation.  It delegates nonce fetching and token
    verification to the :class:`~mock_ca.attestation_verifier.AttestationVerifier`
    stored in ``self._verifier``.  Subclasses (e.g.
    ``mock_ca.remote_att_mockca.RemoteAttestationHandler``) inject a concrete
    verifier and may override :meth:`_get_nonce` for hint-based resolution.
    """

    def __init__(self, config: Optional[RemoteAttestationConfig] = None):
        """Initialize the remote attestation handler.

        :param config: The remote attestation configuration containing nonce settings,
                      verifier endpoints, and validation rules. If None, uses default configuration.
        """
        self.config = config or RemoteAttestationConfig()
        self.nonce_config = self.config.attestation_nonce_config
        self._saved_nonces: List[NonceVerifierEntry] = []
        # Concrete verifier injected by subclasses or the caller.
        self._verifier: Optional[AttestationVerifier] = None

    def _get_nonce(self, nonce_request: NonceRequestASN1) -> bytes:
        """Get a nonce value for the attestation challenge.

        Uses ``self._verifier`` when set; otherwise falls back to a
        self-generated nonce or returns empty bytes.

        Per draft-ietf-lamps-attestation-freshness section 3.1, if the CA/RA
        cannot provide a requested nonce it MUST return an empty OCTET STRING.

        :param nonce_request: The nonce request containing the optional verifier hint.
        :return: The nonce value as bytes, or empty bytes (b"") if unable to provide.
        """
        nonce_size = self.nonce_config.min_nonce_length or 32

        if self._verifier is not None:
            nonce = self._verifier.get_nonce(nonce_size)
            if nonce:
                return nonce

        if not self.nonce_config.allow_self_generated_nonce:
            return b""

        logging.info("Generating self-generated nonce (%d bytes)", nonce_size)
        return os.urandom(nonce_size)

    def _save_nonce_verifier_entry(self, tx_id: bytes, nonce: bytes, evidence_type: univ.ObjectIdentifier) -> None:
        """Save the nonce verifier entry for later validation.

        Stores the issued nonce along with the transaction ID, evidence type, and creation time.
        This enables later validation when the client submits attestation evidence containing
        the nonce. Empty nonces (indicating failure to provide a nonce) are not saved.

        :param tx_id: The transaction ID of the CMP message.
        :param nonce: The nonce value that was issued to the client.
        :param evidence_type: The OID identifying the attestation evidence type (e.g., PSA, CCA).
        """
        evidence = evidence_type if evidence_type.isValue else None
        if nonce != b"":
            self._saved_nonces.append(
                NonceVerifierEntry(nonce=nonce, evidence_type=evidence, created_time=datetime.now(), tx_id=tx_id)
            )

    def process_attr_type_and_value_entry(
        self, nonce_requests: NonceRequestValueASN1, tx_id: bytes
    ) -> rfc9480.InfoTypeAndValue:
        """Process nonce requests from a CMP general message and generate responses.

        Validates each nonce request, generates or retrieves the appropriate nonce,
        creates nonce responses, and tracks issued nonces for future validation.
        This implements the server-side nonce freshness protocol from
        draft-ietf-lamps-attestation-freshness section 3.

        :param nonce_requests: Sequence of NonceRequest structures from the client,
                              each potentially requesting different nonce parameters.
        :param tx_id: The transaction ID of the CMP request, used for tracking issued nonces.
        :return: InfoTypeAndValue with infoType=id-it-nonceResponse and infoValue containing
                the DER-encoded NonceResponseValue (sequence of NonceResponse structures).
        :raises RemoteAttestationError: If the nonce request sequence is empty.
        :raises BadNonceRequest: If any nonce request fails validation (e.g., invalid length).
        """
        if len(nonce_requests) == 0:
            raise RemoteAttestationError("The nonce request is empty.")

        nonce_responses = NonceResponseValueASN1()

        for nonce_request in nonce_requests:
            validate_nonce_request(nonce_request, min_nonce_length=self.nonce_config.min_nonce_length)
            nonce_value = self._get_nonce(nonce_request)
            nonce_response = prepare_nonce_response_from_request(
                nonce_request,
                nonce_value=nonce_value,
                min_nonce_length=self.nonce_config.min_nonce_length,
                expiry_time=self.nonce_config.expiration_time,
            )
            self._save_nonce_verifier_entry(tx_id, nonce_value, nonce_request["type"])
            nonce_responses.append(nonce_response)

        logging.debug("Prepared nonce responses: %s", nonce_responses.prettyPrint())
        info_value = rfc9480.InfoTypeAndValue()
        info_value["infoType"] = id_it_nonceResponse
        info_value["infoValue"] = encoder.encode(nonce_responses)
        return info_value

    def _validate_nonce_verifier_entry(self):
        """Validate the nonce verifier entry against stored values.

        This method would verify that a nonce presented in attestation evidence matches
        a previously issued nonce, checking expiration time and evidence type.

        :raises NotImplementedError: This validation is not yet implemented.
        """
        raise NotImplementedError("Nonce verifier entry validation is not implemented yet.")

    @staticmethod
    def csr_contains_attestation_bundle(csr: rfc6402.CertificationRequest) -> bool:
        """Check if the CSR contains a draft-22 `AttestationBundle` attribute.

        :param csr: The PKCS#10 certification request to examine.
        :return: True if the CSR contains the id-aa-attestation attribute, False otherwise.
        """
        return csr_contains_attribute(csr, id_aa_attestation)

    @staticmethod
    def csr_contains_attestation_evidence(csr: rfc6402.CertificationRequest) -> bool:
        """Backward-compatible alias for checking draft-22 attestation bundle presence.

        :param csr: The PKCS#10 certification request to examine.
        :return: True if the CSR contains the id-aa-attestation attribute, False otherwise.
        """
        return RemoteAttestationHandler.csr_contains_attestation_bundle(csr)

    @staticmethod
    def _decode_csr_attestation_bundle(csr: rfc6402.CertificationRequest) -> AttestationBundle:
        """Extract and decode the draft-22 `AttestationBundle` from a CSR.

        :param csr: The certification request containing the id-aa-attestation attribute.
        :return: Decoded AttestationBundle.
        :raises RemoteAttestationError: If the CSR does not contain attestation evidence.
        :raises BadAsn1Data: If the attestation bundle fails ASN.1 decoding.
        """
        try:
            return get_attestation_evidence_attribute(csr)
        except ValueError as err:
            raise RemoteAttestationError(str(err)) from err

    def process_csr_attestation_bundle(self, csr: rfc6402.CertificationRequest) -> Tuple[bool, Optional[str]]:
        """Process a draft-22 attestation bundle from a CSR.

        Extracts and processes the `AttestationBundle` CSR attribute. The bundle may carry
        evidence, endorsements, attestation results, or other statements defined by
        `AttestationStatementSet`.

        :param csr: The certification request containing the id-aa-attestation attribute.
        :return: Tuple of (success: bool, error_message: Optional[str]).
        :raises RemoteAttestationError: If the CSR does not contain attestation evidence.
        :raises BadAsn1Data: If the attestation bundle fails ASN.1 decoding.
        :raises NotImplementedError: Processing logic is not yet implemented.
        """
        bundle = self._decode_csr_attestation_bundle(csr)
        return self._handle_attestation_bundle(bundle)

    def verify_csr_remote_attestation(self, csr: bytes) -> Tuple[bool, Optional[str]]:
        """Verify remote attestation in a CSR.

        High-level method to verify remote attestation bundle content in a CSR.

        :param csr: The DER-encoded certification request.
        :return: Tuple of (success: bool, error_message: Optional[str]).
        :raises NotImplementedError: This method is not yet implemented.
        """
        raise NotImplementedError("CSR remote attestation verification is not implemented yet.")

    def process_csr_remote_attestation(self, csr: bytes) -> Tuple[bool, Optional[str]]:
        """Process remote attestation in a CSR.

        High-level method to process remote attestation bundle content in a CSR.

        :param csr: The DER-encoded certification request.
        :return: Tuple of (success: bool, error_message: Optional[str]).
        :raises NotImplementedError: This method is not yet implemented.
        """
        raise NotImplementedError("CSR remote attestation processing is not implemented yet.")

    def process_crmf_remote_attestation(self, crmf: bytes) -> Tuple[bool, Optional[str]]:
        """Process remote attestation in a CRMF (Certificate Request Message Format) request.

        Handles attestation evidence in CRMF requests used with CMP certification requests.

        :param crmf: The DER-encoded CRMF request.
        :return: Tuple of (success: bool, error_message: Optional[str]).
        :raises NotImplementedError: This method is not yet implemented.
        """
        raise NotImplementedError("CRMF remote attestation processing is not implemented yet.")

    def _handle_attestation_bundle(self, bundle: AttestationBundle) -> Tuple[bool, Optional[str]]:
        """Handle and process a draft-22 attestation bundle.

        Processes statements from a decoded `AttestationBundle` and applies policy checks
        for nonce freshness, statement types, and certificate-chain constraints.

        :param bundle: The parsed `AttestationBundle` structure.
        :return: Tuple of (success: bool, error_message: Optional[str]).
        :raises NotImplementedError: This handler is not yet implemented.
        """
        raise NotImplementedError("Attestation bundle handling is not implemented yet.")
