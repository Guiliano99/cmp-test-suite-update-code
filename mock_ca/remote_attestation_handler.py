# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Remote attestation handler for CMP MockCA.

This module implements remote attestation functionality for the CMP MockCA
test server, supporting nonce freshness mechanisms and attestation evidence
processing as defined in:

* draft-ietf-lamps-attestation-freshness — Nonce-based freshness for attestation
* draft-ietf-lamps-csr-attestation        — CSR attestation evidence attributes

Architecture (per ``constraint.md`` §9 revised, §10 added)
----------------------------------------------------------
The MockCA owns nonce state.  At GenM time the handler delegates nonce
generation and verifier-routing decisions to a :class:`NonceHandler`,
which:

1. Generates the nonce locally (``os.urandom``).
2. Resolves the destination verifier URL using the
   ``oid > fallback`` precedence (the freshness draft has no hint field).
3. Stores the (nonce, verifier_url) pair under
   ``(tx_id, evidence_oid_der, instance)`` for one-shot consumption at
   IR time.

This handler exposes the GenM-facing API
(``process_attr_type_and_value_entry``).  The IR-time dispatch lives in
:class:`mock_ca.rats_handler.RatsHandler`, which calls
``NonceHandler.consume`` per ``AttestationStatement``.

For the Veraison-specific subclass that wires up the NonceHandler from
environment variables see ``mock_ca.remote_att_mockca.RemoteAttestationHandler``.
"""

from __future__ import annotations

import logging
from typing import Optional

from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc6402, rfc9480

from mock_ca.db_config_vars import RemoteAttestationConfig
from mock_ca.nonce_handler import ID_TCG_ATTEST_QUOTE, NonceHandler, SystemFailure
from pq_logic.tmp_oids import id_it_nonceResponse
from resources.certextractutils import csr_contains_attribute
from resources.exceptions import RemoteAttestationError
from resources.remote_att_utils.attest_nonce_freshness_structures import (
    NonceRequestASN1,
)
from resources.remote_att_utils.csr_attest_structures import id_aa_attestation
from resources.remote_attestation_utils import (
    prepare_nonce_response_from_request,
    validate_nonce_request,
)


class RemoteAttestationHandler:
    """Handler for nonce issuance in CMP RATS GenM/GenP exchanges.

    Holds a :class:`NonceHandler` (set by the constructor or a subclass)
    that owns all per-tx nonce state and verifier-routing decisions.

    The handler is a base class.  The concrete configuration that wires up
    the NonceHandler from env vars lives in
    ``mock_ca.remote_att_mockca.RemoteAttestationHandler`` to keep
    deployment-specific code separated from upstream-mergeable logic.

    Construction:

    * ``RemoteAttestationHandler(config, nonce_handler=nh)`` — pre-built
      handler injected by tests or by a subclass.
    * ``RemoteAttestationHandler(config)`` — leaves ``self.nonce_handler``
      as ``None``.  Calling ``process_attr_type_and_value_entry`` in this
      state raises a clear error; the deployment must wire one up.
    """

    def __init__(
        self,
        config: Optional[RemoteAttestationConfig] = None,
        nonce_handler: Optional[NonceHandler] = None,
    ):
        self.config = config or RemoteAttestationConfig()
        self.nonce_config = self.config.attestation_nonce_config
        self.nonce_handler: Optional[NonceHandler] = nonce_handler

    # ── GenM-facing API ───────────────────────────────────────────────────────

    def process_attr_type_and_value_entry(
        self, nonce_request: NonceRequestASN1, tx_id: bytes
    ) -> rfc9480.InfoTypeAndValue:
        """Process the ``id-it-nonceRequest`` ITAV in a CMP GenM body.

        Per the attestation-freshness draft the ITAV value is a single
        ``NonceRequest``.  The :class:`NonceHandler` issues a nonce bound to
        a verifier URL; the result is packed into a single ``NonceResponse``
        for the GenP reply.

        :param nonce_request:
            ``NonceRequest`` decoded from the GenM ITAV.
        :param tx_id:
            CMP transactionID.  The nonce issued in this call is stored
            under this tx_id and consumed under the same tx_id at IR time.

        :raises RemoteAttestationError: if the request is not set.
        :raises BadNonceRequest:        if the entry fails validation.
        :raises SystemFailure:          if the NonceHandler cannot resolve a
                                        verifier route.
        :raises RuntimeError:           if no NonceHandler was wired up.
        """
        if not nonce_request.isValue:
            raise RemoteAttestationError("The nonce request is empty.")

        if self.nonce_handler is None:
            raise RuntimeError(
                "RemoteAttestationHandler: no NonceHandler configured. "
                "Inject one via the constructor or use the subclass that "
                "wires one up from environment variables."
            )

        logging.debug("Processing nonce request for tx_id=%s", tx_id.hex())

        validate_nonce_request(
            nonce_request, min_nonce_length=self.nonce_config.min_nonce_length
        )

        type_oid_dot = (
            str(nonce_request["type"]) if nonce_request["type"].isValue else None
        )
        evidence_oid_dot, evidence_oid_der = self._map_type_to_evidence_oid(type_oid_dot)
        proposed_hash_alg_id = self._extract_proposed_hash_alg_id(
            nonce_request, type_oid_dot
        )

        try:
            state = self.nonce_handler.issue(
                tx_id=tx_id,
                evidence_oid_dot=evidence_oid_dot,
                evidence_oid_der=evidence_oid_der,
                proposed_hash_alg_id=proposed_hash_alg_id,
            )
        except SystemFailure:
            # Re-raise so the CMP layer maps it to PKIFailureInfo: systemFailure.
            raise

        nonce_response = prepare_nonce_response_from_request(
            nonce_request,
            nonce_value=state.nonce,
            min_nonce_length=self.nonce_config.min_nonce_length,
            expiry_time=self.nonce_config.expiration_time,
            resp_info=state.resp_info,
        )

        logging.debug("Prepared nonce response: %s", nonce_response.prettyPrint())
        info_value = rfc9480.InfoTypeAndValue()
        info_value["infoType"] = id_it_nonceResponse
        info_value["infoValue"] = encoder.encode(nonce_response)
        return info_value

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _map_type_to_evidence_oid(
        self,
        type_oid_dot: Optional[str],
    ) -> tuple[Optional[str], Optional[bytes]]:
        """Map ``NonceRequest.type`` to the evidence-statement OID.

        Per the freshness draft the request ``type`` identifies the
        reqInfo/respInfo *syntax*, not the evidence-statement type.  For the
        TPM platform profile, the configured ``TPM_PCR_SELECTION_OID`` syntax
        belongs to the ``TcgAttestQuote`` statement: nonces are stored and
        verifier routes resolved under the statement OID so IR-time dispatch
        (which only sees ``AttestationStatement.type``) finds them.

        Unknown or absent types map to ``(None, None)`` — the nonce is then
        stored positionally and routed via the fallback URL.
        """
        if type_oid_dot is None:
            return None, None
        evidence_oid = type_oid_dot
        if (
            self.nonce_handler is not None
            and type_oid_dot == self.nonce_handler.tpm_pcr_selection_oid
        ):
            evidence_oid = ID_TCG_ATTEST_QUOTE
        der = bytes(encoder.encode(univ.ObjectIdentifier(evidence_oid)))
        return evidence_oid, der

    @staticmethod
    def _extract_proposed_hash_alg_id(
        nonce_request: "NonceRequestASN1",
        type_oid_dot: "Optional[str]",
    ) -> "Optional[int]":
        """Return the attester's proposed ``hashAlgId`` from ``reqInfo``, or None.

        When ``NonceRequest.type`` matches the configured
        ``TPM_PCR_SELECTION_OID``, decodes ``reqInfo`` as a
        ``TpmAttestationParams`` and returns the ``hashAlgId`` field.
        Returns ``None`` when absent or undecodable.
        """
        req_info = nonce_request["reqInfo"]
        if not req_info.isValue or type_oid_dot is None:
            return None
        # Local import to keep libattest as an optional dep at import time:
        from libattest.formats.tpm import (  # noqa: PLC0415
            decode_tpm_attestation_params,
            resolve_tpm_pcr_selection_oid,
        )

        if type_oid_dot != resolve_tpm_pcr_selection_oid():
            return None
        try:
            _, hash_alg_id = decode_tpm_attestation_params(bytes(req_info))
        except ValueError:
            return None
        return hash_alg_id

    @staticmethod
    def csr_contains_attestation_bundle(csr: rfc6402.CertificationRequest) -> bool:
        """Check if the CSR contains a draft-22 ``AttestationBundle`` attribute."""
        return csr_contains_attribute(csr, id_aa_attestation)
