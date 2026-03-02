# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
# type: ignore
"""ASN.1 structures for remote-attestation nonce freshness.

This module defines the pyasn1 types used for the nonce freshness exchange in
CMP General Messages, as specified in
`draft-ietf-lamps-attestation-freshness-05`.

Workflow implemented around these structures
--------------------------------------------
1. Client creates one or more `NonceRequestASN1` entries
   (`len`, `type`, `hint` as needed).
2. Requests are wrapped in `NonceRequestValueASN1` (`SEQUENCE OF`) and sent in
   a CMP `InfoTypeAndValue` with `infoType = id-it-nonceRequest`.
3. RA/CA decodes and validates each request, then obtains or generates a nonce.
4. RA/CA returns `NonceResponseASN1` entries (nonce, optional expiry/type/hint)
   wrapped in `NonceResponseValueASN1` with
   `infoType = id-it-nonceResponse`.
5. The requester uses the returned nonce when preparing attestation evidence
   for the subsequent certification request.

Repository integration points
-----------------------------
- Request/response preparation and validation helpers:
  `resources.remote_attestation_utils`
- Server-side processing for CMP general messages:
  `mock_ca.remote_attestation_handler.RemoteAttestationHandler`

Design notes
------------
- `type` is modeled as `OBJECT IDENTIFIER` representing
  `EVIDENCE-STATEMENT.&id`.
- `hint` is modeled as `UTF8String`.
- `NonceRequestValueASN1` and `NonceResponseValueASN1` require at least one
  entry (`SIZE (1..MAX)`).
- These structures are draft-specific and kept local until the draft is
  published as an RFC.

Reference: https://datatracker.ietf.org/doc/draft-ietf-lamps-attestation-freshness/
Implemented draft version: 05
"""

from pyasn1.type import char, constraint, namedtype, univ

_MAX_SEQ_SIZE = float("inf")


class NonceRequestASN1(univ.Sequence):
    """Defines the ASN.1 structure for the `NonceRequest`.

    NonceRequest::= SEQUENCE {
       len INTEGER OPTIONAL,
       -- indicates the required length of the requested nonce.
       type EVIDENCE-STATEMENT.&id({EvidenceStatementSet}) OPTIONAL,
       -- indicates which Evidence type to request a nonce for.
       hint UTF8String OPTIONAL
       -- indicates which Verifier to request a nonce from.
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("len", univ.Integer()),
        # Modeled as OID corresponding to EVIDENCE-STATEMENT.&id
        namedtype.OptionalNamedType("type", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("hint", char.UTF8String()),
    )


class NonceRequestValueASN1(univ.SequenceOf):
    """Defines the ASN.1 structure for the `NonceRequestValue`.

    NonceRequestValue::= SEQUENCE SIZE (1..MAX) OF NonceRequest
    """

    componentType = NonceRequestASN1()
    subtypeSpec = constraint.ValueSizeConstraint(1, _MAX_SEQ_SIZE)


class NonceResponseASN1(univ.Sequence):
    """Defines the ASN.1 structure for the `NonceResponse`.

    NonceResponse::= SEQUENCE {
        nonce OCTET STRING,
        -- contains the nonce of length len
        -- provided by the Verifier indicated with hint.
        expiry INTEGER OPTIONAL,
        -- indicates how long in seconds the Verifier considers the nonce valid.
        type EVIDENCE-STATEMENT.&id({EvidenceStatementSet}) OPTIONAL,
        -- indicates which Evidence type to request a nonce for.
        hint UTF8String OPTIONAL
        -- indicates which Verifier to request a nonce from.
     }

    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("nonce", univ.OctetString()),
        namedtype.OptionalNamedType("expiry", univ.Integer()),
        # Modeled as OID corresponding to EVIDENCE-STATEMENT.&id
        namedtype.OptionalNamedType("type", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("hint", char.UTF8String()),
    )


class NonceResponseValueASN1(univ.SequenceOf):
    """Defines the ASN.1 structure for the `NonceResponseValue`.

    NonceResponseValue::= SEQUENCE SIZE (1..MAX) OF NonceResponse
    """

    componentType = NonceResponseASN1()
    subtypeSpec = constraint.ValueSizeConstraint(1, _MAX_SEQ_SIZE)
