# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Compatibility imports for CMP remote-attestation nonce freshness structures."""

from libattest.formats.csrattest import (
    NonceRequest,
    NonceRequestASN1,
    NonceRequestTypeInfo,
    NonceResponse,
    NonceResponseASN1,
    NonceResponseTypeInfo,
    id_it_nonceRequest,
    id_it_nonceResponse,
    nonce_request_info,
    nonce_request_type_oid,
    nonce_response_info,
    nonce_response_type_oid,
)

__all__ = [
    "NonceRequest",
    "NonceRequestASN1",
    "NonceRequestTypeInfo",
    "NonceResponse",
    "NonceResponseASN1",
    "NonceResponseTypeInfo",
    "id_it_nonceRequest",
    "id_it_nonceResponse",
    "nonce_request_info",
    "nonce_request_type_oid",
    "nonce_response_info",
    "nonce_response_type_oid",
]
