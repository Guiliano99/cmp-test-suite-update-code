# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Compatibility imports for TPM attestation structures used by MockCA."""

from libattest.formats.tpm import (
    TcgAttestCertify,
    id_tcg_attest_certify,
    prepare_tcg_attest_certify,
)

__all__ = [
    "TcgAttestCertify",
    "id_tcg_attest_certify",
    "prepare_tcg_attest_certify",
]
