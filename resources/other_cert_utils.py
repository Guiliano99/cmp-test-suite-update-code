# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Helper for RFC 4212 alternative certificate formats, like an `AttributeCertificate` or an OpenPGP certificate."""

from typing import Optional, Union

from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc5755, rfc9480
from robot.api.deco import keyword, not_keyword

from resources import asn1utils, convertutils, oid_mapping, prepare_alg_ids, prepareutils
from resources.typingutils import GeneralNamesType, PublicKey


def _convert_cert_or_pub_key_to_der(
    cert_or_pub_key: Union[rfc9480.CMPCertificate, PublicKey, rfc5280.SubjectPublicKeyInfo], use_pub_key: bool
) -> bytes:
    """Convert a CMPCertificate or public key to DER-encoded bytes."""
    if not use_pub_key and isinstance(cert_or_pub_key, rfc5280.SubjectPublicKeyInfo):
        raise TypeError(
            f"Invalid cert_or_pub_key type: {type(cert_or_pub_key)}. Got: {cert_or_pub_key}. "
            f"Use use_pub_key=True to extract the public key from a `SubjectPublicKeyInfo` structure."
        )

    if isinstance(cert_or_pub_key, rfc5280.SubjectPublicKeyInfo):
        return asn1utils.encode_to_der(cert_or_pub_key)

    if isinstance(cert_or_pub_key, rfc9480.CMPCertificate) and not use_pub_key:
        return asn1utils.encode_to_der(cert_or_pub_key)
    if isinstance(cert_or_pub_key, rfc9480.CMPCertificate) and use_pub_key:
        return asn1utils.encode_to_der(cert_or_pub_key["tbsCertificate"]["subjectPublicKeyInfo"])
    if not isinstance(cert_or_pub_key, PublicKey):
        raise TypeError(f"Invalid cert_or_pub_key type: {type(cert_or_pub_key)}. Got: {cert_or_pub_key}.")

    spki = convertutils.subject_public_key_info_from_pubkey(cert_or_pub_key)
    return asn1utils.encode_to_der(spki)


def _parse_digest_object_type(
    object_type: Union[str, int],
) -> int:
    """Parse the object type for `ObjectDigestInfo` (from rfc5755) structure.

    :param object_type: The object type as string or integer.
    :return: The object type as integer.
    """
    if isinstance(object_type, int):
        return object_type
    object_type_str = str(object_type).lower()
    # For reference, see rfc5755:
    # rfc5755.ObjectDigestInfo
    if object_type_str == "publickey":
        return 0
    if object_type_str == "publickeycert":
        return 1
    if object_type_str == "otherobjecttypes":
        return 2
    raise ValueError(f"Invalid object type: {object_type}")


@not_keyword
def prepare_object_digest_info_structure(
    digest_algorithm: rfc5280.AlgorithmIdentifier,
    object_type: Union[str, int],
    digest: bytes,
    other_object_type_id: Optional[univ.ObjectIdentifier] = None,
    target: Optional[rfc5755.ObjectDigestInfo] = None,
) -> rfc5755.ObjectDigestInfo:
    """Prepare an `ObjectDigestInfo` structure.

    This structure is used to identify an object (e.g., a public key or a certificate) by its digest.
    It is typically used within a `Holder` structure to identify the entity associated with an
    Attribute Certificate.

    :param digest_algorithm: The digest algorithm identifier.
    :param object_type: The object type.
    :param digest: The object digest bytes.
    :param other_object_type_id: The otherObjectTypeID value.
    :param target: Optional `ObjectDigestInfo` object to populate.
    :return: The populated `ObjectDigestInfo` structure.
    """
    obj_digest_info = rfc5755.ObjectDigestInfo().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
    )
    if target is not None:
        obj_digest_info = target

    obj_digest_info["digestAlgorithm"] = digest_algorithm
    obj_digest_info["digestedObjectType"] = univ.Enumerated(_parse_digest_object_type(object_type))
    if other_object_type_id is not None:
        obj_digest_info["otherObjectTypeID"] = other_object_type_id
    obj_digest_info["objectDigest"] = univ.BitString.fromOctetString(digest)
    return obj_digest_info


@keyword("Prepare ObjectDigestInfo")
def prepare_object_digest_info(  # noqa: D417 undocumented params
    cert_or_pub_key: Optional[Union[rfc9480.CMPCertificate, PublicKey, rfc5280.SubjectPublicKeyInfo]],
    hash_alg: str = "sha256",
    bad_digest: bool = False,
    der_data: Optional[bytes] = None,
) -> rfc5755.ObjectDigestInfo:
    """Prepare an `ObjectDigestInfo` structure from a CMPCertificate.

    Arguments:
    ---------
        - `cert_or_pub_key`: CMPCertificate or public key to create the ObjectDigestInfo for.
        - `hash_alg`: Hash algorithm to use for the digest. Defaults to "sha256".
        - `bad_digest`: Whether to use a bad digest value. Defaults to `False`.
        - `der_data`: Optional DER-encoded data to compute the digest from.

    Returns:
    -------
        - The populated `ObjectDigestInfo` structure.

    Raises:
    ------
        - `TypeError`: If `cert_or_pub_key` is not a CMPCertificate or public key or a `SubjectPublicKeyInfo` structure.
        - `ValueError`: If `hash_alg` is not a valid hash algorithm.

    Examples:
    --------
    | ${obj_digest_info} | Prepare ObjectDigestInfo | ${cert} | hash_alg=sha256 |
    | ${obj_digest_info} | Prepare ObjectDigestInfo | ${public_key} | hash_alg=sha256 | True |

    """
    if cert_or_pub_key is None and der_data is None:
        raise ValueError("Either cert_or_pub_key or der_data must be provided.")
    if cert_or_pub_key is not None and der_data is not None:
        raise ValueError("Only one of `cert_or_pub_key` or `der_data` can be provided.")

    if isinstance(cert_or_pub_key, rfc9480.CMPCertificate):
        digest_obj_type = "publicKeyCert"
        der_data = _convert_cert_or_pub_key_to_der(cert_or_pub_key, use_pub_key=False)
    elif isinstance(cert_or_pub_key, PublicKey):
        digest_obj_type = "publicKey"
        der_data = _convert_cert_or_pub_key_to_der(cert_or_pub_key, use_pub_key=True)
    else:
        digest_obj_type = "otherObjectTypes"

    if der_data is None:
        raise ValueError("`der_data` must be provided or derived from cert_or_pub_key.")

    digest = oid_mapping.compute_hash(
        data=der_data,
        alg_name=hash_alg,
        bad_digest=bad_digest,
    )
    digest_algorithm = prepare_alg_ids.prepare_sha_alg_id(hash_alg)
    return prepare_object_digest_info_structure(
        digest_algorithm=digest_algorithm,
        object_type=digest_obj_type,
        digest=digest,
    )
@not_keyword
def prepare_issuer_serial_structure(
    issuer: GeneralNamesType,
    serial_number: int,
    issuer_uid: Optional[bytes] = None,
    target: Optional[rfc5755.IssuerSerial] = None,
) -> rfc5755.IssuerSerial:
    """Prepare an `IssuerSerial` structure.

    This structure identifies a certificate by its issuer's name and serial number.
    It is used within a `Holder` structure to identify the base certificate of the Attribute Certificate holder.

    :param issuer: The issuer name.
    :param serial_number: The serial number.
    :param issuer_uid: The issuer unique identifier. Defaults to `None`.
    :param target: Optional `IssuerSerial` object to populate.
    """
    issuer_serial = rfc5755.IssuerSerial().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
    if target is not None:
        issuer_serial = target

    issuer_serial["issuer"] = prepareutils.parse_to_general_names(issuer)
    issuer_serial["serial"] = serial_number
    if issuer_uid is not None:
        issuer_serial["issuerUID"] = rfc5280.UniqueIdentifier.fromOctetString(issuer_uid)
    return issuer_serial

