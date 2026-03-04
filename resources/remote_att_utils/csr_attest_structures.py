# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
# draft-ietf-lamps-csr-attestation-22
# type: ignore
"""ASN.1 structures for CSR Attestation.

Implements the types defined in:
  draft-ietf-lamps-csr-attestation-22, Appendix B – ASN.1 Module

These structures are draft-specific and must be kept local to this repository
until the document is published as an RFC.

Reference: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-csr-attestation-22
"""

from typing import List, Union

from pyasn1.type import constraint, namedtype, tag, univ
from pyasn1_alt_modules import rfc9480

# ---------------------------------------------------------------------------
# Object Identifier
# ---------------------------------------------------------------------------

# id-aa-attestation OBJECT IDENTIFIER ::= { id-aa 59 }
# draft-ietf-lamps-csr-attestation-22, Section 4.3
id_aa_attestation = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 2, 59))

# ---------------------------------------------------------------------------
# OtherCertificateFormat
# ---------------------------------------------------------------------------


# OtherCertificateFormat ::= SEQUENCE {
#     otherCertFormat  OTHER-CERT-FMT.&id({SupportedCertFormats}),
#     otherCert        OTHER-CERT-FMT.&Type({SupportedCertFormats}{@otherCertFormat})
# }
# draft-ietf-lamps-csr-attestation-22, Section 4.1 (reproduced from RFC 6268)
class OtherCertificateFormat(univ.Sequence):
    """Non-X.509 certificate format wrapper (open type, OID + content)."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("otherCertFormat", univ.ObjectIdentifier()),
        namedtype.NamedType("otherCert", univ.Any()),
    )


# ---------------------------------------------------------------------------
# LimitedCertChoices
# ---------------------------------------------------------------------------


# LimitedCertChoices ::= CertificateChoices
#   (WITH COMPONENTS { certificate, other })
#
# This is CertificateChoices restricted to only 'certificate' and 'other'
# (i.e. extendedCertificate, v1AttrCert, v2AttrCert are excluded).
# draft-ietf-lamps-csr-attestation-22, Section 4.1
class LimitedCertChoices(univ.Choice):
    """CertificateChoices restricted to 'certificate' and 'other'.

    The [3] IMPLICIT tag on 'other' preserves the encoding of
    CertificateChoices per CMS (RFC 6268).
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("certificate", rfc9480.CMPCertificate()),
        namedtype.NamedType(
            "other",
            OtherCertificateFormat().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    3,
                )
            ),
        ),
    )


# ---------------------------------------------------------------------------
# AttestationStatement
# ---------------------------------------------------------------------------


# AttestationStatement ::= SEQUENCE {
#     type           ATTESTATION-STATEMENT.&id({AttestationStatementSet}),
#     stmt           ATTESTATION-STATEMENT.&Type(
#                        {AttestationStatementSet}{@type})
# }
# draft-ietf-lamps-csr-attestation-22, Section 4.1, Figure 1
class AttestationStatement(univ.Sequence):
    """Single attestation statement (Evidence, Endorsement, or AR).

    The 'stmt' field carries the raw attestation payload as an open type.
    Formats that are not ASN.1-encoded MUST be wrapped in an OCTET STRING.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.NamedType("stmt", univ.Any()),
    )


# ---------------------------------------------------------------------------
# AttestationBundle
# ---------------------------------------------------------------------------


# Helper: SEQUENCE SIZE (1..MAX) OF AttestationStatement
# draft-ietf-lamps-csr-attestation-22, Section 4.1, Figure 2
class AttestationSequence(univ.SequenceOf):
    """A collection of AttestationStatement objects.

    AttestationSequence ::= SEQUENCE SIZE (1..MAX) OF AttestationStatement

    """

    componentType = AttestationStatement()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))


# Helper: SEQUENCE SIZE (1..MAX) OF LimitedCertChoices
# draft-ietf-lamps-csr-attestation-22, Section 4.1, Figure 2
class AttestCertSequence(univ.SequenceOf):
    """Non-empty sequence of `LimitedCertChoices` used by `AttestationBundle.certs`."""

    componentType = LimitedCertChoices()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))


# AttestationBundle ::= SEQUENCE {
#     attestations  SEQUENCE SIZE (1..MAX) OF AttestationStatement,
#     certs         SEQUENCE SIZE (1..MAX) OF LimitedCertChoices OPTIONAL
# }
# draft-ietf-lamps-csr-attestation-22, Section 4.1, Figure 2
class AttestationBundle(univ.Sequence):
    """Container carried in a PKCS#10 attribute or CRMF extension.

    'attestations' holds one or more AttestationStatement objects.
    'certs' is an unordered collection of certificates that may be needed
    to validate any of the AttestationStatement instances.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attestations", AttestationSequence()),
        namedtype.OptionalNamedType("certs", AttestCertSequence()),
    )


def _prepare_stmt(stmt: Union[univ.Sequence, bytes]) -> Union[univ.Sequence, univ.Any]:
    """Wrap a raw bytes statement in `univ.Any` so it can be assigned to the open-type `stmt` field.

    :param stmt: The attestation statement payload. Either an already-constructed
        pyasn1 `Sequence` (assigned as-is) or raw `bytes` that will be wrapped
        in a `univ.Any` instance so that pyasn1 treats the value as an opaque
        DER blob.
    :return: The original `Sequence` unchanged, or a `univ.Any` wrapping the
        supplied bytes.
    """
    if isinstance(stmt, bytes):
        stmt = univ.Any(stmt)  # type: ignore
    return stmt


def prepare_attestation_statement(
    stmt_id: univ.ObjectIdentifier,
    stmt: Union[univ.Sequence, bytes],
) -> AttestationStatement:
    """Prepare an `AttestationStatement` structure for a CSR attribute.

    Args:
        stmt_id: OID identifying the attestation statement format.
        stmt: Statement payload as ASN.1 object or raw DER bytes.

    Returns:
        A populated `AttestationStatement`.

    Constructs and populates an `AttestationStatement` as defined in
    draft-ietf-lamps-csr-attestation, Section 4.1.

    Arguments:
    ---------
        - `stmt_id`: OID that identifies the attestation-statement format
          (e.g. the TCG *id-tcg-attest-certify* OID).  Assigned verbatim to
          the `type` field of the resulting structure.
        - `stmt`: The attestation payload.  Pass a pyasn1 `Sequence` sub-type
          to include an already-constructed ASN.1 object, or pass `bytes`
          containing a DER-encoded blob; bytes are wrapped in `univ.Any` via
          `_prepare_stmt`.

    Returns:
    -------
        - A fully populated `AttestationStatement` instance ready for
          inclusion in an `AttestationBundle`.

    Raises:
    ------
        - No explicit exceptions are raised; invalid pyasn1 assignments will
          propagate as `pyasn1` errors from the underlying library.

    Examples:
    --------
    | ${stmt}= | Prepare Attestation Statement | ${oid} | ${der_bytes} |
    | ${stmt}= | Prepare Attestation Statement | ${oid} | ${sequence} |

    """
    attestation_statement = AttestationStatement()
    attestation_statement["type"] = stmt_id
    attestation_statement["stmt"] = _prepare_stmt(stmt)
    return attestation_statement


def _parse_certs_to_limited_choices(certs: list[rfc9480.CMPCertificate]) -> list[LimitedCertChoices]:
    """Convert a list of X.509 certificates to a list of `LimitedCertChoices` with the 'certificate' option."""
    out = []
    for x in certs:
        if isinstance(x, rfc9480.CMPCertificate):
            out.append(LimitedCertChoices().setComponentByName("certificate", x))
        elif isinstance(x, OtherCertificateFormat):
            out.append(LimitedCertChoices().setComponentByName("other", x))
        elif isinstance(x, LimitedCertChoices):
            out.append(x)
        else:
            raise TypeError(f"Unexpected type {type(x)} in list of certificates")
    return out


def prepare_attestation_bundle(
    attestations: list[AttestationStatement],
    certs: list[Union[rfc9480.CMPCertificate, LimitedCertChoices]] | None = None,
) -> AttestationBundle:
    """Prepare an `AttestationBundle` structure for a CSR attribute.

    Args:
        attestations: Non-empty list of attestation statements.
        certs: Optional certificates used to validate statements.

    Returns:
        A populated `AttestationBundle`.

    Constructs an `AttestationBundle` as defined in
    draft-ietf-lamps-csr-attestation-22, Section 4.1. The bundle groups one
    or more `AttestationStatement` objects together with an optional
    unordered certificate collection needed to validate them.

    Arguments:
    ---------
        - `attestations`: Non-empty list of `AttestationStatement` objects to
          include in the `attestations` field.
        - `certs`: Optional list of `LimitedCertChoices` objects (X.509
          certificates or other certificate formats) that may be needed to
          validate one or more of the `AttestationStatement` instances.  Pass
          `None` (default) to omit the optional `certs` field.

    Returns:
    -------
        - A fully populated `AttestationBundle` ready to be DER-encoded and
          embedded in a PKCS#10 attribute or CRMF extension.

    Raises:
    ------
        - No explicit exceptions are raised; invalid pyasn1 assignments will
          propagate as `pyasn1` errors from the underlying library.

    Examples:
    --------
    | ${bundle}= | Prepare Attestation Bundle | ${attestations} |
    | ${bundle}= | Prepare Attestation Bundle | ${attestations} | certs=${certs} |

    """
    bundle = AttestationBundle()
    bundle["attestations"].extend(attestations)
    if certs is not None:
        bundle["certs"].extend(_parse_certs_to_limited_choices(certs))  # type: ignore
    return bundle


def get_attestation_bundle_certs(attestation_bundle: AttestationBundle) -> List[rfc9480.CMPCertificate]:
    """Get X.509 certificates from an `AttestationBundle`.

    :param attestation_bundle: The `AttestationBundle` to extract certificates from.
    :return: A list of `CMPCertificate`.
    """
    if not attestation_bundle["certs"].isValue:
        return []

    certs = []
    for entry in attestation_bundle["certs"]:
        if entry.getName() != "certificate":
            raise NotImplementedError("Only certificates are supported.")
        certs.append(entry["certificate"])
    return certs
