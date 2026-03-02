# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

# TPM 2.0 attestation structures
"""ASN.1 structures for TPM 2.0 attestation and other formats.

Defines local ASN.1 types used to carry TPM 2.0 attestation data that can be
embedded in an AttestationStatement (see csr_attest_structures.py).

These structures are repository-local draft helpers and are not defined in a
published RFC.
"""

from typing import Optional

from pyasn1.type import namedtype, univ

# ---------------------------------------------------------------------------
# TcgAttestCertify
# ---------------------------------------------------------------------------

id_tcg_attest_certify = univ.ObjectIdentifier("2.23.133.20.1")


class TcgAttestCertify(univ.Sequence):
    """Defines the ASN.1 structure for the `TcgAttestCertify` for a TPM2.0.

    TcgAttestCertify ::= SEQUENCE {
        tpmSAttest        OCTET STRING,
        -- The TPMS_ATTEST structure.
        signature        OCTET STRING,
        -- The TPMT_SIGNATURE structure.
        tpmTPublic      OCTET STRING OPTIONAL
        -- The TPMT_PUBLIC structure.
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tpmSAttest", univ.OctetString()),
        namedtype.NamedType("signature", univ.OctetString()),
        namedtype.OptionalNamedType("tpmTPublic", univ.OctetString()),
    )


def prepare_tcg_attest_certify(
    tpm_s_attest: bytes, signature: bytes, tpm_tpublic: Optional[bytes] = None
) -> TcgAttestCertify:
    """Prepare a TcgAttestCertify structure for a TPM 2.0 attestation.

    :param tpm_s_attest: The TPMS_ATTEST structure.
    :param signature: The TPMT_SIGNATURE structure.
    :param tpm_tpublic: The TPMT_PUBLIC structure.
    :return: A populated TcgAttestCertify structure.
    """
    tcg_attest_certify = TcgAttestCertify()
    tcg_attest_certify["tpmSAttest"] = tpm_s_attest
    tcg_attest_certify["signature"] = signature
    if tpm_tpublic is not None:
        tcg_attest_certify["tpmTPublic"] = tpm_tpublic
    return tcg_attest_certify
