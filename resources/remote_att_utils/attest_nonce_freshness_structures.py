# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Compatibility imports for CMP remote-attestation nonce freshness structures."""

from libattest.formats.csrattest import (
    NonceRequest,
    NonceRequestASN1,
    NonceResponse,
    NonceResponseASN1,
    id_it_nonceRequest,
    id_it_nonceResponse,
)

__all__ = [
    "NonceRequest",
    "NonceRequestASN1",
    "NonceResponse",
    "NonceResponseASN1",
    "id_it_nonceRequest",
    "id_it_nonceResponse",
]
