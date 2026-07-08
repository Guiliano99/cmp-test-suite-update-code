# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Compatibility imports for CSR attestation structures used by MockCA."""

from libattest.formats.csrattest import (
    AttestationBundle,
    AttestationSequence,
    AttestationStatement,
    AttestCertSequence,
    LimitedCertChoices,
    OtherCertificateFormat,
    get_attestation_bundle_certs,
    id_aa_attestation,
    prepare_attestation_bundle,
    prepare_attestation_statement,
    prepare_opaque_attestation_statement,
)

__all__ = [
    "AttestCertSequence",
    "AttestationBundle",
    "AttestationSequence",
    "AttestationStatement",
    "LimitedCertChoices",
    "OtherCertificateFormat",
    "get_attestation_bundle_certs",
    "id_aa_attestation",
    "prepare_attestation_bundle",
    "prepare_attestation_statement",
    "prepare_opaque_attestation_statement",
]
