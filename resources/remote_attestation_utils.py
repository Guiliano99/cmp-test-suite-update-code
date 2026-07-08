# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
"""Helpers for remote-attestation nonce exchange and CSR attestation bundle handling."""

import logging
import os
from typing import List, Optional

from pyasn1.type import univ
from pyasn1.type.char import UTF8String
from pyasn1_alt_modules import rfc6402, rfc9480
from robot.api.deco import keyword, not_keyword

from pq_logic.tmp_oids import (
    id_cca_platform_attestation_token_evidence,
    id_it_nonceRequest,
    id_psa_attestation_token_evidence,
)
from resources import asn1utils, certutils
from resources.asn1utils import try_decode_pyasn1
from resources.certextractutils import csr_contains_attribute, csr_get_attribute
from resources.exceptions import BadAsn1Data, BadNonceRequest, BadRemoteAttestationASN1, RemoteAttestationError
from resources.oidutils import ATTESTATION_TYPE_2_STRUCTURE, ATTESTATION_TYPE_OID_2_NAME
from resources.remote_att_utils.attest_nonce_freshness_structures import (
    NonceRequestASN1,
    NonceRequestTypeInfo,
    NonceResponseASN1,
    NonceResponseTypeInfo,
    nonce_request_type_oid,
)
from resources.remote_att_utils.csr_attest_structures import (
    AttestationBundle,
    AttestationSequence,
    AttestCertSequence,
    id_aa_attestation,
)


@not_keyword
def validate_nonce_request(
    nonce_request: NonceRequestASN1,
    min_nonce_length: Optional[int] = 32,
    strict_type_validation: bool = False,
) -> None:
    """Validate the nonce request.

    :param nonce_request: The nonce request to validate.
    :param min_nonce_length: Minimum length of the nonce in bytes. Defaults to `32` (skipped if `None`)
    :param strict_type_validation: Whether to enforce strict type validation.
        Defaults to `False` (must be a known attestation type).
    :raises BadRequest: If the nonce request is invalid.
    """
    if min_nonce_length is not None:
        if nonce_request["len"].isValue:
            nonce = nonce_request["len"]
            if len(nonce) < min_nonce_length:
                raise BadNonceRequest(f"Nonce length {len(nonce)} is less than minimum length {min_nonce_length}.")

    # Per the freshness draft, reqInfo MUST be omitted when type is absent.
    # This is now structurally enforced: reqInfo lives inside reqTypeInfo,
    # which mandates type, so the old violation is no longer representable.

    atte_type_oid = nonce_request_type_oid(nonce_request)
    if atte_type_oid is not None:
        atte_type = univ.ObjectIdentifier(atte_type_oid)
        if atte_type not in ATTESTATION_TYPE_OID_2_NAME and strict_type_validation:
            raise RemoteAttestationError(f"Attestation type '{atte_type}' is not supported.")


@keyword(name="Prepare NonceRequest")
def prepare_nonce_request(
    nonce_length: Optional[int] = None,
    evidence_type: Optional[str] = None,
    req_info: Optional[bytes] = None,
) -> NonceRequestASN1:
    """Prepare a `NonceRequestASN1` structure for remote attestation nonce requests.

    Args:
        nonce_length: Optional requested nonce length.
        evidence_type: Optional type OID string identifying the reqInfo syntax.
        req_info: Optional DER bytes of the type-specific request value
            (requires `evidence_type` per the freshness draft).

    Returns:
        A populated `NonceRequestASN1`.

    Arguments:
    ---------
        - `nonce_length`: Optional nonce length in bytes.
        - `evidence_type`: Optional type OID as dotted string.
        - `req_info`: Optional DER bytes for the `reqInfo` open type.

    Returns:
    -------
        - A populated `NonceRequestASN1` structure.

    Raises:
    ------
        - `ValueError`: If `req_info` is given without `evidence_type`.

    Examples:
    --------
    | ${nonce_req}= | Prepare NonceRequest | nonce_length=32 |
    | ${nonce_req}= | Prepare NonceRequest | evidence_type=1.3.6.1.4.1.99999.3 | req_info=${der} |

    """
    if req_info is not None and evidence_type is None:
        raise ValueError("reqInfo requires the type field (freshness draft).")

    nonce_req = NonceRequestASN1()
    if nonce_length is not None:
        nonce_req["len"] = nonce_length

    if evidence_type is not None:
        req_type_info = NonceRequestTypeInfo()
        req_type_info["type"] = evidence_type
        if req_info is not None:
            req_type_info["reqInfo"] = univ.Any(req_info)
        nonce_req["reqTypeInfo"] = req_type_info

    return nonce_req


@keyword(name="Prepare Nonce Request InfoTypeAndValue")
def prepare_nonce_request_info_type_and_value(
    nonce_request: NonceRequestASN1,
) -> rfc9480.InfoTypeAndValue:
    """Prepare a `CMP InfoTypeAndValue` structure carrying a nonce request.

    Args:
        nonce_request: The nonce request to encode.

    Returns:
        An `InfoTypeAndValue` carrying a DER `NonceRequestASN1`.

    Per the attestation-freshness draft, the `infoType` is set to
    `id-it-nonceRequest` and `infoValue` contains a single DER encoded
    `NonceRequestASN1` (not a SEQUENCE OF).

    Arguments:
    ---------
        - `nonce_request`: A `NonceRequestASN1` entry.

    Returns:
    -------
        - A populated `rfc9480.InfoTypeAndValue` structure.

    Raises:
    ------
        - `ValueError`: If `nonce_request` is `None`.
        - `Exception`: If ASN.1 encoding fails.

    Examples:
    --------
    | ${nonce_req}= | Prepare NonceRequest | nonce_length=32 |
    | ${info_val}= | Prepare Nonce Request InfoTypeAndValue | ${nonce_req} |

    """
    if nonce_request is None:
        raise ValueError("nonce_request cannot be None")

    info_type_and_value = rfc9480.InfoTypeAndValue()
    info_type_and_value["infoType"] = id_it_nonceRequest
    info_type_and_value["infoValue"] = univ.Any(asn1utils.encode_to_der(nonce_request))

    return info_type_and_value


def _parse_nonce(
    pos_nonce_length: univ.Integer,
    nonce_value: Optional[bytes] = None,
    min_nonce_length: Optional[int] = 32,
    bad_nonce_length: bool = False,
) -> bytes:
    """Parse or generate a nonce value.

    :param pos_nonce_length: The length of the nonce in bytes.
    :param nonce_value: The nonce value to use. If `None`, a random nonce will be generated.
    :param min_nonce_length: Minimum length of the nonce in bytes. Defaults to `32` (skipped if `None`)
    :param bad_nonce_length: Whether to raise an exception if the nonce length is invalid. Defaults to `False`.
    :return: The nonce value.
    """
    nonce_length = int(pos_nonce_length) if pos_nonce_length.isValue else None  # type: ignore
    if nonce_length is not None and bad_nonce_length:
        nonce_length: int
        if min_nonce_length is not None and nonce_length < min_nonce_length:
            raise BadNonceRequest(f"Nonce length {nonce_length} is less than minimum length {min_nonce_length}.")
        if nonce_length <= 0:
            raise BadNonceRequest(f"Nonce length must be positive, got {nonce_length}.")
        return os.urandom(nonce_length - 1)

    if nonce_value is not None:
        if nonce_length is not None and len(nonce_value) < nonce_length:
            logging.debug(f"Nonce value {nonce_value} is shorter than expected length {nonce_length}.")
        return nonce_value

    if nonce_length is None and min_nonce_length is not None:
        nonce_length = min_nonce_length

    elif nonce_length is None and min_nonce_length is None:
        return os.urandom(32)

    if min_nonce_length is None:
        min_nonce_length = 32

    if nonce_length < min_nonce_length:
        raise BadNonceRequest(f"Nonce length {nonce_length} is less than minimum length {min_nonce_length}.")

    if nonce_length <= 0:
        raise BadNonceRequest(f"Nonce length must be positive, got {nonce_length}.")

    return os.urandom(nonce_length)


def _parse_bad_type(nonce_request: NonceRequestASN1) -> univ.ObjectIdentifier:
    """Parse a different attestation type for the nonce response.

    :param nonce_request: The nonce request.
    :return: The modified attestation type.
    :raises ValueError: If the attestation type cannot be modified.
    """
    atte_type_oid = nonce_request_type_oid(nonce_request)
    if atte_type_oid is None:
        return list(ATTESTATION_TYPE_OID_2_NAME.keys())[0]

    atte_type = univ.ObjectIdentifier(atte_type_oid)
    for x in ATTESTATION_TYPE_OID_2_NAME:
        if x != atte_type:
            return x

    raise ValueError("Could not find a different attestation type to set in nonce response.")


@not_keyword
def prepare_nonce_response_from_request(
    nonce_request: NonceRequestASN1,
    nonce_value: Optional[bytes] = None,
    min_nonce_length: Optional[int] = 32,
    expiry_time: Optional[int] = None,
    bad_type: bool = False,
    bad_nonce_length: bool = False,
    resp_info: Optional[bytes] = None,
) -> NonceResponseASN1:
    """Prepare a NonceResponse object from a NonceRequest.

    Per the freshness draft, the response ``type`` is defined by the request
    ``type`` and ``respInfo`` MUST be omitted when ``type`` is absent.

    :param nonce_request: The NonceRequest object.
    :param nonce_value: The nonce value to include in the response.
    :param min_nonce_length: Minimum length of the nonce in bytes. Defaults to `32` (skipped if `None`)
    :param expiry_time: The expiry time of the nonce in seconds. Defaults to `None`.
    :param bad_type: Whether to set a mismatching attestation type (negative tests). Defaults to `False`.
    :param bad_nonce_length: Whether to return a too-short nonce (negative tests). Defaults to `False`.
    :param resp_info: Optional DER bytes of the type-specific response value
        (e.g. ``TpmAttestationParams`` — PCR list + negotiated hash
        algorithm — for the TPM platform profile).  ``None`` ↔ field omitted.
    :return: The populated NonceResponse object.
    """
    nonce_response = NonceResponseASN1()
    nonce_response["nonce"] = _parse_nonce(nonce_request["len"], nonce_value, min_nonce_length, bad_nonce_length)

    if bad_type:
        resp_type = _parse_bad_type(nonce_request)
    else:
        atte_type_oid = nonce_request_type_oid(nonce_request)
        resp_type = univ.ObjectIdentifier(atte_type_oid) if atte_type_oid is not None else None

    if expiry_time is not None:
        nonce_response["expiry"] = expiry_time

    if resp_type is not None:
        resp_type_info = NonceResponseTypeInfo()
        resp_type_info["type"] = resp_type
        if resp_info is not None:
            resp_type_info["respInfo"] = univ.Any(resp_info)
        nonce_response["respTypeInfo"] = resp_type_info
    elif resp_info is not None:
        logging.warning(
            "prepare_nonce_response_from_request: dropping respInfo because "
            "the response carries no type (draft: respInfo requires type)"
        )

    return nonce_response


@not_keyword
def validate_evidence_bundle_certs(evidence_bundle_certs: AttestCertSequence) -> List[rfc9480.CMPCertificate]:
    """Validate certificates in an `AttestationBundle`."""
    if len(evidence_bundle_certs) == 0:
        raise BadRemoteAttestationASN1("AttestationBundle must contain at least one certificate.")

    cert_list: List[rfc9480.CMPCertificate] = []

    for cert in evidence_bundle_certs:
        if not cert.isValue:
            raise BadRemoteAttestationASN1("AttestationBundle must contain only `certificate` or `other` choices.")

        cert_name = cert.getName()
        if cert_name not in {"certificate", "other"}:
            raise BadRemoteAttestationASN1(
                f"AttestationBundle must contain only `certificate` or `other`, got {cert_name}."
            )

        if cert_name == "certificate":
            cert_list.append(cert["certificate"])
        else:
            raise NotImplementedError("Other certificates are not supported yet.")

    return cert_list


@not_keyword
def validate_attestation_bundle(attestation_bundle: AttestationBundle) -> None:
    """Validate an `AttestationBundle`."""
    if attestation_bundle["certs"].isValue:
        validate_evidence_bundle_certs(attestation_bundle["certs"])


@not_keyword
def validate_attestation_result_bundle(attestation_result_bundle: AttestationBundle) -> None:
    """Backward-compatible wrapper for validating an `AttestationBundle`."""
    validate_attestation_bundle(attestation_result_bundle)


def get_attestation_evidence_attribute(csr: rfc6402.CertificationRequest) -> AttestationBundle:
    """Extract and decode the attestation evidence attribute from a CSR.

    Args:
        csr: Certification request containing `id_aa_attestation`.

    Returns:
        Decoded `AttestationBundle`.

    Arguments:
    ---------
        - `csr`: Certification request containing `id_aa_attestation`.

    Returns:
    -------
        - A decoded `AttestationBundle`.

    Raises:
    ------
        - `ValueError`: If the CSR does not contain attestation evidence.
        - `BadAsn1Data`: If the evidence attribute is malformed.

    Examples:
    --------
    | ${csr}= | Parse CSR | ${csr_der} |
    | ${evidence}= | Get Attestation Evidence Attribute | ${csr} |

    """
    if not csr_contains_attribute(csr, id_aa_attestation):
        raise ValueError("CSR does not contain attestation attribute.")

    attr = csr_get_attribute(csr, id_aa_attestation)
    if attr is None:
        raise ValueError("CSR does not contain attestation attribute.")

    if len(attr["attrValues"]) != 1:
        raise BadAsn1Data(
            f"CSR contains multiple `attrValues` entries for the remote attestation evidence. Got: {attr.prettyPrint()}"
        )

    obj, rest = asn1utils.try_decode_pyasn1(attr["attrValues"][0], AttestationBundle())  # type: ignore
    obj: AttestationBundle
    if rest:
        raise BadAsn1Data("AttestationBundle")
    return obj


def pretty_print_evidence_statement(evidence_statement: AttestationSequence) -> AttestationSequence:
    """Decode known statement formats to improve readability of evidence statements.

    Args:
        evidence_statement: Sequence of attestation statements to normalize.

    Returns:
        Sequence with decoded known statement payloads.

    Arguments:
    ---------
        - `evidence_statement`: Sequence of `AttestationStatement` objects to normalize.

    Returns:
    -------
        - An `AttestationStatement` sequence with decoded payloads where supported.

    Raises:
    ------
        - `Exception`: If decoding of a statement payload fails.

    Examples:
    --------
    | ${pretty}= | Pretty Print Evidence Statement | ${evidence_statement} |

    """
    out = AttestationSequence()
    for statement in evidence_statement:
        if statement["type"] in ATTESTATION_TYPE_2_STRUCTURE:
            obj, _ = try_decode_pyasn1(
                statement["stmt"],
                ATTESTATION_TYPE_2_STRUCTURE[statement["type"]].clone(),
            )  # type: ignore
            obj: asn1utils.Asn1Type
            statement["stmt"] = obj

        if statement["type"] in [id_psa_attestation_token_evidence, id_cca_platform_attestation_token_evidence]:
            statement["stmt"] = UTF8String(statement["stmt"].asOctets().decode("utf-8"))

        out.append(statement)
    return out


@keyword(name="Validate EvidenceBundle")
def validate_evidence_bundle(evidence_bundle: AttestationBundle, crl_check: bool) -> None:
    """Validate certificates inside an `AttestationBundle`.

    Args:
        evidence_bundle: Bundle containing statements and certificate set.
        crl_check: Whether to run CRL checking during chain validation.

    Returns:
        `None`.

    Arguments:
    ---------
        - `evidence_bundle`: Bundle containing evidence statements and certificate set.
        - `crl_check`: Whether CRL checking is enabled during certificate-chain validation.

    Returns:
    -------
        - `None`.

    Raises:
    ------
        - `BadRemoteAttestationASN1`: If the certificate bundle structure is invalid.
        - `NotImplementedError`: Always raised after certificate validation (function not fully implemented).

    Examples:
    --------
    | Validate EvidenceBundle | ${evidence_bundle} | crl_check=${True} |

    """
    if not evidence_bundle["certs"].isValue:
        raise BadRemoteAttestationASN1("AttestationBundle does not contain certificates.")

    cert_list = validate_evidence_bundle_certs(evidence_bundle["certs"])
    certutils.verify_cert_chain_openssl(cert_list, crl_check=crl_check)
    raise NotImplementedError("Validate evidence bundle not implemented yet.")


def pretty_print_csr_attestation(csr: rfc6402.CertificationRequest) -> str:
    """Render attestation evidence from a CSR into a human-readable text form.

    Args:
        csr: Certification request containing attestation evidence attributes.

    Returns:
        Human-readable representation of the decoded attestation bundle.

    Arguments:
    ---------
        - `csr`: Certification request containing attestation evidence attributes.

    Returns:
    -------
        - A string representation of the CSR attestation evidence.

    Raises:
    ------
        - `ValueError`: If the CSR does not contain attestation evidence.
        - `BadAsn1Data`: If the evidence attribute is malformed.

    Examples:
    --------
    | ${text}= | Pretty Print CSR Attestation | ${csr} |

    """
    attestation_bundle = get_attestation_evidence_attribute(csr)

    # Decode statement payloads only for known OIDs; leave unknown statements untouched.
    pretty_attestations = pretty_print_evidence_statement(attestation_bundle["attestations"])

    out = AttestationBundle()
    out["attestations"].extend(pretty_attestations)
    if attestation_bundle["certs"].isValue:
        out["certs"].extend(attestation_bundle["certs"])

    return out.prettyPrint()
