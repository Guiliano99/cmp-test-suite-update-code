# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""CMP GenM/GenP nonce-issuance adapter over the :mod:`libattest.ra` engine.

This handler is the thin CMP adapter for the nonce-issuance leg of remote
attestation, per:

* draft-ietf-lamps-attestation-freshness — nonce-based freshness, and
* draft-ietf-lamps-csr-attestation        — CSR attestation evidence.

The reusable RA orchestration — resolving a profile for a ``NonceRequest.type``,
parsing the type-specific ``reqInfo``, negotiating the ``respInfo``, and
validating + packaging the ``NonceResponse`` (including the response-type OID,
which for some profiles legitimately differs from the request type) — lives
in :class:`libattest.ra.RemoteAttestationEngine`.  This module keeps only the
CMP-specific work:

1. decode the ``NonceRequest`` ITAV,
2. pull the ``type`` OID + ``reqInfo`` bytes + ``len`` + transactionID from the
   CMP carrier,
3. call :meth:`RemoteAttestationEngine.build_nonce_response`, and
4. pack the resulting ``NonceResponse`` into an ITAV for GenP.

There is **no per-type branching** here: the engine resolves the profile and
builds the respInfo.  The concrete env-wired subclass lives in
``mock_ca.remote_att_mockca.RemoteAttestationHandler``.
"""

from __future__ import annotations

import logging
from typing import Optional

from libattest.formats.csrattest import (
    NonceRequestASN1,
    id_it_nonceResponse,
    nonce_request_info,
    nonce_request_type_oid,
)
from libattest.ra import BadNonceRequest, RemoteAttestationEngine
from pyasn1_alt_modules import rfc9480

from mock_ca.db_config_vars import RemoteAttestationConfig
from resources.asn1utils import encode_to_der
from resources.exceptions import BadNonceRequest as CmpBadNonceRequest
from resources.exceptions import RemoteAttestationError


class RemoteAttestationHandler:
    """CMP adapter for nonce issuance in RATS GenM/GenP exchanges.

    Holds a :class:`libattest.ra.RemoteAttestationEngine` (set by the constructor
    or a subclass) that owns the profile registry and the nonce store.  Both the
    GenM (issue) and the IR (consume) legs share **one** engine — the CA wires
    the same handler into the :class:`mock_ca.rats_handler.RatsHandler`, so there
    is a single nonce lifecycle per CA.

    Construction:

    * ``RemoteAttestationHandler(config, engine=eng)`` — explicit engine
      (tests / subclass);
    * ``RemoteAttestationHandler(config)`` — leaves ``self.engine`` as ``None``;
      calling :meth:`process_attr_type_and_value_entry` then raises a clear
      error (the deployment must wire an engine up).
    """

    def __init__(
        self,
        config: Optional[RemoteAttestationConfig] = None,
        engine: Optional[RemoteAttestationEngine] = None,
    ) -> None:
        """Wire the handler to a config and (optionally) an RA engine."""
        self.config = config or RemoteAttestationConfig()
        self.nonce_config = self.config.attestation_nonce_config
        self.engine: Optional[RemoteAttestationEngine] = engine

    # ── GenM-facing API ───────────────────────────────────────────────────────

    def process_attr_type_and_value_entry(
        self, nonce_request: NonceRequestASN1, tx_id: bytes
    ) -> rfc9480.InfoTypeAndValue:
        """Process the ``id-it-nonceRequest`` ITAV in a CMP GenM body.

        Per the attestation-freshness draft the ITAV value is a single
        ``NonceRequest``.  The engine issues a nonce for the request type,
        builds the type-specific ``respInfo``, and packages the full
        ``NonceResponse`` (with the correct response-type OID); the result is
        packed into a single ``NonceResponse`` ITAV for the GenP reply.

        :param nonce_request: ``NonceRequest`` decoded from the GenM ITAV.
        :param tx_id: CMP transactionID; the nonce is filed under this id and
            consumed under it at IR time.
        :raises RemoteAttestationError: if the request is not set.
        :raises BadNonceRequest:        if the entry fails validation.
        :raises RuntimeError:           if no engine was wired up.
        """
        if not nonce_request.isValue:
            raise RemoteAttestationError("The nonce request is empty.")

        if self.engine is None:
            raise RuntimeError(
                "RemoteAttestationHandler: no RemoteAttestationEngine configured. "
                "Inject one via the constructor or use the subclass that wires "
                "one up from environment variables."
            )

        logging.debug("Processing nonce request for tx_id=%s", tx_id.hex())

        requested_len = int(nonce_request["len"]) if nonce_request["len"].isValue else None

        try:
            nonce_response = self.engine.build_nonce_response(
                tx_id,
                nonce_request_type_oid(nonce_request),
                req_info=nonce_request_info(nonce_request),
                requested_len=requested_len,
                min_nonce_length=self.nonce_config.min_nonce_length,
                expiry_time=self.nonce_config.expiration_time,
            )
        except BadNonceRequest as exc:
            raise CmpBadNonceRequest(str(exc)) from exc

        logging.debug("Prepared nonce response: %s", nonce_response.prettyPrint())
        info_value = rfc9480.InfoTypeAndValue()
        info_value["infoType"] = id_it_nonceResponse
        info_value["infoValue"] = encode_to_der(nonce_response)
        return info_value


__all__ = ["RemoteAttestationHandler"]
