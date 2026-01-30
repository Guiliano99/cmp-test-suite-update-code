# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Helper for RFC 4212 alternative certificate formats."""

from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence, Union

from pyasn1.codec.der import encoder
from pyasn1.type import base, tag, univ
from pyasn1_alt_modules import rfc4211, rfc4212, rfc5280, rfc5755, rfc9480
from robot.api.deco import keyword, not_keyword

from resources import asn1utils, compareutils, convertutils, oid_mapping, prepare_alg_ids, prepareutils, protectionutils
from resources.exceptions import BadCertTemplate, BadRequest
from resources.typingutils import GeneralNamesType, PublicKey, SignKey


class BadAttributeCertTemplate(BadCertTemplate):
    """Raised when an invalid attribute certificate template is provided."""


class BadAttributeCert(BadCertTemplate):
    """Raised when an invalid attribute certificate is provided."""


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


def _encode_other_cert_value(
    other_cert: Union[bytes, base.Asn1Item],
) -> bytes:
    """Encode the otherCert value if needed.

    :param other_cert: DER-encoded bytes or a pyasn1 object to encode.
    :return: DER-encoded bytes of the otherCert value.
    """
    if isinstance(other_cert, base.Asn1Item):
        return encoder.encode(other_cert)
    return other_cert


def _prepare_optional_att_cert_validity(
    not_before_time: Optional[Union[str, float, datetime]] = None,
    not_after_time: Optional[Union[str, float, datetime]] = None,
) -> rfc4212.OptionalAttCertValidity:
    """Prepare an RFC 4212 `OptionalAttCertValidity` structure.

    :param not_before_time: The notBeforeTime value.
    :param not_after_time: The notAfterTime value.
    :return: The populated `OptionalAttCertValidity` structure.
    """
    validity = rfc4212.OptionalAttCertValidity()
    if not_before_time is not None:
        validity["notBeforeTime"] = prepareutils.prepare_generalized_time(not_before_time).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
    if not_after_time is not None:
        validity["notAfterTime"] = prepareutils.prepare_generalized_time(not_after_time).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
    return validity


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
    """Prepare an RFC 4212 `ObjectDigestInfo` structure.

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
def prepare_object_digest_info( # noqa: D417 undocumented params
    cert_or_pub_key: Optional[Union[rfc9480.CMPCertificate, PublicKey, rfc5280.SubjectPublicKeyInfo]],
    hash_alg: str = "sha256",
    bad_digest: bool = False,
    der_data: Optional[bytes] = None,
) -> rfc5755.ObjectDigestInfo:
    """Prepare an RFC 4212 `ObjectDigestInfo` structure from a CMPCertificate.

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


def validate_object_digest_info(
    cert_or_pub_key: Union[rfc9480.CMPCertificate, PublicKey],
    object_digest_info: rfc5755.ObjectDigestInfo,
) -> None:
    """Validate an RFC 4212 `ObjectDigestInfo` structure against a CMPCertificate or public key.

    :param cert_or_pub_key: The CMPCertificate or the public key to validate the ObjectDigestInfo against.
    :param object_digest_info: The ObjectDigestInfo structure to validate.
    """
    digest_obj_type = object_digest_info["digestedObjectType"]
    digest = object_digest_info["objectDigest"].asOctets()
    if digest_obj_type == 0:
        der_data = _convert_cert_or_pub_key_to_der(cert_or_pub_key, use_pub_key=True)
    elif digest_obj_type == 1:
        der_data = _convert_cert_or_pub_key_to_der(cert_or_pub_key, use_pub_key=False)
    else:
        other_oid = None
        if object_digest_info["otherObjectTypeID"].isValue:
            other_oid = oid_mapping.may_return_oid_to_name(object_digest_info["otherObjectTypeID"])
        raise BadRequest(f"Not Implemented to compute the digest of the following object type: {other_oid}")

    computed_digest = oid_mapping.compute_hash_from_alg_id(object_digest_info["digestAlgorithm"], der_data)
    if computed_digest != digest:
        raise BadRequest(
            f"Invalid digest for object type {digest_obj_type}. Expected: {digest.hex()}, got: {computed_digest.hex()}"
        )
    return None


@not_keyword
def prepare_issuer_serial_structure(
    issuer: GeneralNamesType,
    serial_number: int,
    issuer_uid: Optional[bytes] = None,
    target: Optional[rfc5755.IssuerSerial] = None,
) -> rfc5755.IssuerSerial:
    """Prepare an RFC 4212 `IssuerSerial` structure.

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


@not_keyword
def prepare_issuer_serial_from_cert(
    cert: rfc9480.CMPCertificate,
    target: Optional[rfc5755.IssuerSerial] = None,
) -> rfc5755.IssuerSerial:
    """Prepare an RFC 4212 `IssuerSerial` structure from a CMPCertificate.

    This is a helper function to extract the issuer and serial number from a certificate
    and create the `IssuerSerial` structure used to identify the base certificate.

    :param cert: The CMPCertificate to extract the issuer serial from.
    :param target: Optional `IssuerSerial` object to populate.
    :return: The prepared `IssuerSerial` structure.
    """
    uid = cert["tbsCertificate"]["issuerUniqueID"]
    issuer_uid = uid.asOctets() if uid.isValue else None
    return prepare_issuer_serial_structure(
        cert["tbsCertificate"]["issuer"], cert["tbsCertificate"]["serialNumber"], issuer_uid=issuer_uid, target=target
    )


def _patch_holder_structure_with_base_cert_id(
    holder: rfc4212.Holder,
    base_certificate_id: Optional[Union[rfc9480.CMPCertificate, rfc5755.IssuerSerial]] = None,
) -> rfc5755.Holder:
    """Patch the `Holder` structure with the issuer unique identifier of the certificate."""
    if base_certificate_id is None:
        return holder

    if isinstance(base_certificate_id, rfc5755.IssuerSerial):
        holder["baseCertificateID"]["issuer"] = base_certificate_id["issuer"]
        holder["baseCertificateID"]["serial"] = base_certificate_id["serial"]
        if base_certificate_id["issuerUID"].isValue:
            holder["baseCertificateID"]["issuerUID"] = base_certificate_id["issuerUID"]

    elif isinstance(base_certificate_id, rfc9480.CMPCertificate):
        target_iss_ser = rfc5755.IssuerSerial().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )
        holder["baseCertificateID"] = prepare_issuer_serial_from_cert(base_certificate_id, target=target_iss_ser)
    else:
        raise TypeError(f"Invalid baseCertificateID type: {type(base_certificate_id)}. Got: {base_certificate_id}.")

    return holder


def prepare_holder_structure(
    base_certificate_id: Optional[Union[rfc9480.CMPCertificate, rfc5755.IssuerSerial]] = None,
    entity_name: Optional[GeneralNamesType] = None,
    object_digest_info: Optional[rfc5755.ObjectDigestInfo] = None,
    target: Optional[rfc4212.Holder] = None,
) -> rfc4212.Holder:
    """Prepare an RFC 4212 `Holder` structure.

    The `Holder` structure identifies the entity to which an Attribute Certificate is issued.
    It can identify the holder by a base certificate (using `IssuerSerial`), by name (`entityName`),
    or by the digest of an object (`ObjectDigestInfo`).

    :param base_certificate_id: The baseCertificateID value.
    :param entity_name: The entityName value.
    :param object_digest_info: The objectDigestInfo value.
    :param target: Optional `Holder` object to populate.
    :return: The populated `Holder` structure.
    """
    holder = rfc4212.Holder().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))

    if target is not None:
        holder = target

    holder = _patch_holder_structure_with_base_cert_id(holder, base_certificate_id)

    if entity_name is not None:
        holder["entityName"].extend(prepareutils.parse_to_general_names(entity_name))
    if object_digest_info is not None:
        holder["objectDigestInfo"] = object_digest_info
    return holder


@not_keyword
def prepare_att_cert_template(
    version: Optional[Union[str, int]] = None,
    holder: Optional[rfc4212.Holder] = None,
    issuer: Optional[rfc4212.AttCertIssuer] = None,
    signature: Optional[rfc4212.AlgorithmIdentifier] = None,
    serial_number: Optional[int] = None,
    not_before_time: Optional[Union[str, float, datetime]] = None,
    not_after_time: Optional[Union[str, float, datetime]] = None,
    attributes: Optional[Sequence[rfc4212.Attribute]] = None,
    issuer_unique_id: Optional[rfc4212.UniqueIdentifier] = None,
    extensions: Optional[rfc4212.Extensions] = None,
    target: Optional[rfc4212.AttCertTemplate] = None,
) -> rfc4212.AttCertTemplate:
    """Prepare an RFC 4212 `AttCertTemplate` structure.

    :param version: The version number.
    :param holder: The holder of the attribute certificate.
    :param issuer: The issuer of the attribute certificate.
    :param signature: The signature algorithm identifier.
    :param serial_number: The serial number of the attribute certificate.
    :param not_before_time: The notBeforeTime value.
    :param not_after_time: The notAfterTime value.
    :param attributes: A sequence of attributes.
    :param issuer_unique_id: The issuer unique identifier.
    :param extensions: The extensions of the attribute certificate.
    :param target: Optional `AttCertTemplate` object to populate.
    :return: The populated `AttCertTemplate` structure.
    """
    att_template = target or rfc4212.AttCertTemplate()
    if version is not None:
        att_template["version"] = int(version)
    if holder is not None:
        att_template["holder"] = holder
    if issuer is not None:
        att_template["issuer"] = issuer
    if signature is not None:
        att_template["signature"] = signature
    if serial_number is not None:
        att_template["serialNumber"] = int(serial_number)

    if not_before_time is not None or not_after_time is not None:
        att_template["attrCertValidityPeriod"] = _prepare_optional_att_cert_validity(
            not_before_time=not_before_time,
            not_after_time=not_after_time,
        )
    if attributes is not None:
        attr_values = univ.SequenceOf(componentType=rfc4212.Attribute())
        for entry in attributes:
            attr_values.append(entry)
        att_template["attributes"] = attr_values
    if issuer_unique_id is not None:
        att_template["issuerUniqueID"] = issuer_unique_id
    if extensions is not None:
        att_template["extensions"].extend(extensions)
    return att_template


@not_keyword
def prepare_alt_cert_template_att_cert(
    att_cert_template: rfc4212.AttCertTemplate,
    target: Optional[rfc4212.AltCertTemplate] = None,
) -> rfc4212.AltCertTemplate:
    """Prepare an RFC 4212 `AltCertTemplate` for an Attribute Certificate template."""
    alt_template = target or rfc4212.AltCertTemplate()
    alt_template["type"] = rfc4212.id_acTemplate
    alt_template["value"] = att_cert_template
    return alt_template


@not_keyword
def prepare_openpgp_cert_template_extended(
    native_template: bytes,
    controls: Optional[rfc4211.Controls] = None,
    target: Optional[rfc4212.OpenPGPCertTemplateExtended] = None,
) -> rfc4212.OpenPGPCertTemplateExtended:
    """Prepare an RFC 4212 `OpenPGPCertTemplateExtended` structure."""
    extended = target or rfc4212.OpenPGPCertTemplateExtended()
    extended["nativeTemplate"] = rfc4212.OpenPGPCertTemplate(native_template)
    if controls is not None:
        extended["controls"] = controls
    return extended


@not_keyword
def prepare_alt_cert_template_openpgp(
    native_template: bytes,
    controls: Optional[rfc4211.Controls] = None,
    target: Optional[rfc4212.AltCertTemplate] = None,
) -> rfc4212.AltCertTemplate:
    """Prepare an RFC 4212 `AltCertTemplate` for an OpenPGP certificate template."""
    alt_template = target or rfc4212.AltCertTemplate()
    alt_template["type"] = rfc4212.id_openPGPCertTemplateExt
    alt_template["value"] = prepare_openpgp_cert_template_extended(
        native_template=native_template,
        controls=controls,
    )
    return alt_template


def _prepare_attr_type_and_value(
    attr_type: univ.ObjectIdentifier, attr_value: base.Asn1Item, bad_data: bool = False
) -> rfc4211.AttributeTypeAndValue:
    """Prepare an `AttributeTypeAndValue` structure from an attribute type and value.

    :param attr_type: The attribute type.
    :param attr_value: The attribute value.
    :param bad_data: Boolean flag indicating whether to include bad data in the attribute value. Defaults to False.
    """
    attr_entry = rfc4211.AttributeTypeAndValue()
    attr_entry["type"] = attr_type
    data = asn1utils.encode_to_der(attr_value)

    if bad_data:
        data += b"0000"

    attr_entry["value"] = univ.Any(data)
    return attr_entry


@not_keyword
def prepare_alt_cert_template(
    other_format: Union[rfc4212.AttCertTemplate, rfc4212.OpenPGPCertTemplateExtended], bad_data: bool = False
) -> rfc4212.AltCertTemplate:
    """Prepare an RFC 4212 `AltCertTemplate` structure for an empty certificate template.

    :param other_format: The other certificate format template.
    :param bad_data: Boolean flag indicating whether to include bad data in the template. Defaults to False.
    :return: The prepared `AltCertTemplate` structure.
    """
    if isinstance(other_format, rfc4212.AttCertTemplate):
        oid = rfc4212.id_acTemplate

    elif isinstance(other_format, rfc4212.OpenPGPCertTemplateExtended):
        oid = rfc4212.id_openPGPCertTemplateExt

    else:
        raise TypeError(f"Invalid other_format type: {type(other_format)}. Got: {other_format}.")

    return _prepare_attr_type_and_value(attr_type=oid, attr_value=other_format, bad_data=bad_data)  # type: ignore


@keyword(name="Prepare AltCertTemplate CertRequest")
def prepare_alt_cert_template_cert_request(  # noqa: D417 undocumented params
    other_cert_format: Union[rfc4212.AttCertTemplate, rfc4212.OpenPGPCertTemplateExtended],
    cert_req_id: Union[str, int] = 0,
    bad_template_data: bool = False,
    bad_controls_data: bool = False,
) -> rfc4211.CertRequest:
    """Prepare an RFC 4211 `CertRequest` structure for a certificate request in a non-standard format.

    Arguments:
    ---------
       - `other_cert_format`: The other certificate format template.
       - `cert_req_id`: The certificate request ID. Defaults to `0`.
       - `bad_template_data`: Boolean flag indicating whether to include bad data in the template. Defaults to `False`.
       - `bad_controls_data`: Boolean flag indicating whether to include bad data in the controls. Defaults to `False`.

    Returns:
    -------
       - The populated `CertRequest` structure.

    Raises:
    ------
       - `TypeError`: If `other_cert_format` is not a valid certificate template type.

    Examples:
    --------
    | ${cert_request} | Prepare AltCertTemplate CertRequest | ${att_cert_template} |
    | ${cert_request} | Prepare AltCertTemplate CertRequest | ${openpgp_cert_template} | cert_req_id=1 | True | True |

    """
    cert_request = rfc4211.CertRequest()

    attr_type_value = prepare_alt_cert_template(other_cert_format, bad_template_data)

    controls_entry = _prepare_attr_type_and_value(
        rfc4212.id_regCtrl_altCertTemplate, attr_type_value, bad_controls_data
    )

    cert_request["controls"].append(controls_entry)
    cert_request["certTemplate"] = rfc4211.CertTemplate()
    cert_request["certReqId"] = int(cert_req_id)
    return cert_request


#######################################
#       Server Implementation         #
#######################################


def _patch_issuer_ser_to_structure(
    structure: rfc4212.AttCertIssuer,
    ca_cert: rfc9480.CMPCertificate,
    issuer_and_ser: Optional[rfc5755.IssuerSerial] = None,
) -> rfc4212.AttCertIssuer:
    """Patch an RFC 4212 `AttCertIssuer` structure with an RFC 5755 `IssuerSerial` structure.

    :param structure: The structure to patch.
    :param ca_cert: The CMPCertificate to extract the issuer from.
    :param issuer_and_ser: Optional pre-constructed `IssuerSerial` structure.
    :return: The patched `AttCertIssuer` structure.
    """
    if not issuer_and_ser:
        issuer_and_ser = prepare_issuer_serial_from_cert(ca_cert)

    structure["issuerSerial"]["issuer"] = issuer_and_ser["issuer"]
    structure["issuerSerial"]["serial"] = issuer_and_ser["serial"]
    if issuer_and_ser["issuerUID"].isValue:
        structure["issuerSerial"]["issuerUID"] = issuer_and_ser["issuerUID"]

    return structure


def _patch_object_digest_info_to_structure(
    structure: rfc5755.V2Form, object_digest_info: Optional[rfc5755.ObjectDigestInfo] = None
) -> rfc5755.V2Form:
    """Patch an RFC 4212 `AttCertIssuer` structure with an RFC 5755 `ObjectDigestInfo` structure.

    :param structure: The structure to patch.
    :param object_digest_info: Optional pre-constructed `ObjectDigestInfo` structure.
    :return: The patched `AttCertIssuer` structure.
    """
    if object_digest_info is None:
        return structure

    structure_obj_digest_info = structure["objectDigestInfo"]

    structure_obj_digest_info["digestedObjectType"] = object_digest_info["digestedObjectType"]
    structure_obj_digest_info["objectDigest"] = object_digest_info["objectDigest"]
    structure_obj_digest_info["digestAlgorithm"] = object_digest_info["digestAlgorithm"]

    if structure_obj_digest_info["otherObjectTypeID"].isValue:
        structure_obj_digest_info["otherObjectTypeID"] = object_digest_info["otherObjectTypeID"]

    return structure


def _patch_v2form_to_structure(
    structure: rfc4212.AttCertIssuer, v2form_structure: Optional[rfc5755.V2Form] = None
) -> rfc4212.AttCertIssuer:
    """Patch an RFC 4212 `AttCertIssuer` structure with an RFC 5755 `V2Form` structure.

    :param structure: The structure to patch.
    :param v2form_structure: Optional pre-constructed `V2Form` structure.
    :return: The patched `AttCertIssuer` structure.
    """
    if v2form_structure is None:
        return structure

    structure["v2Form"]["issuerName"] = v2form_structure["issuerName"]

    if v2form_structure["issuerSerial"].isValue:
        structure["v2Form"]["issuerSerial"] = v2form_structure["issuerSerial"]

    if v2form_structure["digestedObjectType"].isValue:
        structure["v2Form"]["digestedObjectType"] = v2form_structure["digestedObjectType"]

    return structure


def prepare_att_cert_issuer_v2form(
    ca_cert: rfc9480.CMPCertificate,
    add_base_certificate_id: bool = False,
    add_digest_obj_info: bool = False,
    hash_alg: str = "sha256",
    **kwargs,
) -> rfc5755.V2Form:
    """Prepare a V2Form structure for an attribute certificate issuer.

    Populates the V2Form object with the necessary data, including potential adjustments
    based on input parameters. The function allows customization when adding issuer serial
    and digest object information, along with optional overrides through keyword arguments.

    :param ca_cert: Certificate authority (CA) certificate in the form of a CMPCertificate.
    :param add_base_certificate_id: Boolean flag indicating whether to add the issuer's serial
        information in the V2Form. Defaults to True.
    :param add_digest_obj_info: Boolean flag specifying whether to include object digest
        information. Defaults to True.
    :param hash_alg: The hashing algorithm to use for object digest calculations. Defaults to "sha256".
    :param kwargs: Optional keyword arguments. May include:
        - `target`: A pre-constructed V2Form structure to be used as the base.
        - `issuer_name`: Specifies the issuer name override as an alternative to extracting
          from the provided CA certificate.
    :return: A fully prepared instance of V2Form containing all relevant issuer details.
    """
    v_form_structer = rfc5755.V2Form().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))

    if kwargs.get("target") is not None:
        v_form_structer = kwargs["target"]

    if kwargs.get("issuer_name") is not None:
        issuer_name = prepareutils.parse_to_general_names(kwargs["issuer_name"])
    else:
        issuer_name = ca_cert["tbsCertificate"]["issuer"]

    v_form_structer["issuerName"] = prepareutils.parse_to_general_names(issuer_name, "directoryName")

    if add_base_certificate_id:
        iss_ser_target = rfc5755.IssuerSerial().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )

        v_form_structer["baseCertificateID"] = prepare_issuer_serial_from_cert(ca_cert, target=iss_ser_target)

    if add_digest_obj_info:
        if kwargs.get("object_digest_info") is None:
            digest_obj_info = prepare_object_digest_info(ca_cert, hash_alg=hash_alg)
        else:
            digest_obj_info = kwargs["object_digest_info"]

        _form_structer = _patch_object_digest_info_to_structure(v_form_structer, digest_obj_info)

    return v_form_structer


def _prepare_att_cert_issuer(
    ca_cert: rfc9480.CMPCertificate,
    use_formv1: bool = True,
    form_structure: Optional[Union[rfc5755.V2Form, GeneralNamesType]] = None,
    target: Optional[rfc4212.AttCertIssuer] = None,
) -> rfc4212.AttCertIssuer:
    """Prepare an RFC 4212 `AttCertIssuer` structure from a CMPCertificate.

    :param ca_cert: The CMPCertificate to extract the issuer from.
    :param use_formv1: Whether to use the v1Form field instead of the v2Form field. Defaults to `True`.
    :param form_structure: Optional pre-constructed V2Form structure to be used as the base.
    :return: The populated `AttCertIssuer` structure.
    """
    att_cert_issuer = rfc5755.AttCertIssuer()
    if target is not None:
        att_cert_issuer = target

    if use_formv1:
        att_cert_issuer["v1Form"] = prepareutils.parse_to_general_names(
            form_structure or ca_cert["tbsCertificate"]["subject"], "directoryName"
        )
    else:
        att_cert_issuer["v2Form"] = prepare_att_cert_issuer_v2form(ca_cert, form_structure=form_structure)
    return att_cert_issuer


def _patch_attr_cert_issuer_to_structure(
    structure: rfc4212.AttCertTemplate,
    ca_cert: rfc9480.CMPCertificate,
    use_formv1: bool = True,
    form_structure: Optional[Union[rfc5755.V2Form, GeneralNamesType]] = None,
) -> rfc4212.AttCertIssuer:
    """Patch an RFC 4212 `AttCertIssuer` structure with a CMPCertificate issuer.

    :param structure: The structure to patch.
    :param ca_cert: The CMPCertificate to extract the issuer from.
    :param use_formv1: Whether to use the v1Form field instead of the v2Form field. Defaults to `True`.
    :param form_structure: Optional pre-constructed V2Form structure to be used as the base.
    """
    if not structure["issuer"].isValue:
        return _prepare_att_cert_issuer(ca_cert, use_formv1=use_formv1, form_structure=form_structure)

    target = rfc4212.AttCertIssuer()
    form_name = structure["issuer"].getName()
    target[form_name] = structure["issuer"][form_name]
    return target


def _patch_att_cert_validity_to_structure(
    structure: rfc5755.AttCertValidityPeriod,
    not_before_time: Optional[Union[str, float, datetime]] = None,
    not_after_time: Optional[Union[str, float, datetime]] = None,
) -> rfc5755.AttCertValidityPeriod:
    """Patch an RFC 4212 `AttCertTemplate` structure with validity period information.

    :param structure: The structure to patch.
    :param not_before_time: The notBeforeTime value.
    :param not_after_time: The notAfterTime value.
    :return: The patched `AttCertValidityPeriod` structure.
    """
    target = rfc5755.AttCertValidityPeriod()
    if not structure.isValue:
        if not_before_time or not_after_time:
            if not_before_time is None or not_after_time is None:
                raise BadRequest("NotBeforeTime and NotAfterTime must be specified for an attribute certificate.")
        else:
            not_before_time = datetime.now(tz=timezone.utc) - timedelta(days=1)
            not_after_time = not_before_time + timedelta(days=365)

        target["notBeforeTime"] = prepareutils.prepare_generalized_time(not_before_time)
        target["notAfterTime"] = prepareutils.prepare_generalized_time(not_after_time)
        return target

    target["notBeforeTime"] = structure["notBeforeTime"]
    target["notAfterTime"] = structure["notAfterTime"]
    return target


def _build_attribute_cert_info_from_template(
    template: rfc4212.AttCertTemplate,
    signature_alg_id: rfc5280.AlgorithmIdentifier,
    ca_cert: rfc9480.CMPCertificate,
    **kwargs,
) -> rfc5755.AttributeCertificateInfo:
    """Build an RFC 5755 `AttributeCertificateInfo` structure from an RFC 4212 `AttCertTemplate`.

    :param template: The RFC 4212 `AttCertTemplate` structure.
    :param signature_alg_id: The signature algorithm identifier.
    :param ca_cert: The CMPCertificate to extract the issuer from.
    :param kwargs: Optional keyword arguments. May include:
        - `not_before_time`: The notBeforeTime value.
        - `not_after_time`: The notAfterTime value.
    :return: The RFC 5755 `AttributeCertificateInfo` structure.
    """
    info = rfc5755.AttributeCertificateInfo()

    if not template["holder"].isValue:
        raise BadCertTemplate("AttCertTemplate must include holder.")
    if not template["issuer"].isValue:
        raise ValueError("AttCertTemplate must include issuer.")
    if not template["serialNumber"].isValue:
        raise ValueError("AttCertTemplate must include serialNumber.")
    if not template["attrCertValidityPeriod"].isValue:
        raise ValueError("AttCertTemplate must include attrCertValidityPeriod.")
    if not template["attributes"].isValue or len(template["attributes"]) == 0:
        raise BadAttributeCertTemplate("AttCertTemplate must include attributes.")

    if template["version"].isValue:
        if int(template["version"]) != 1:
            raise BadAttributeCertTemplate(
                f"Invalid version number for the AttributeCertTemplate: {int(template['version'])}. "
                f"Only version 1 is supported."
            )

    version = int(template["version"]) if template["version"].isValue else 1

    info["version"] = version
    info["holder"] = template["holder"]
    info["issuer"] = _patch_attr_cert_issuer_to_structure(template, ca_cert=ca_cert)
    info["signature"] = signature_alg_id
    info["serialNumber"] = int(template["serialNumber"])
    info["attrCertValidityPeriod"] = _patch_att_cert_validity_to_structure(
        template["attrCertValidityPeriod"],
        not_after_time=kwargs.get("not_after_time"),
        not_before_time=kwargs.get("not_before_time"),
    )
    info["attributes"].extend(template["attributes"])

    if ca_cert["tbsCertificate"]["issuerUniqueID"].isValue:
        info["issuerUniqueID"] = rfc5755.UniqueIdentifier.fromOctetString(
            ca_cert["tbsCertificate"]["issuerUniqueID"].asOctets()
        )
    elif template["issuerUniqueID"].isValue:
        info["issuerUniqueID"] = rfc5755.UniqueIdentifier.fromOctetString(template["issuerUniqueID"].asOctets())

    if template["extensions"].isValue:
        info["extensions"].extend(template["extensions"])

    return info


@keyword("Build Attribute Certificate From Template")
def build_attribute_cert_from_template(
    template: rfc4212.AttCertTemplate,
    ca_cert: rfc9480.CMPCertificate,
    signing_key: SignKey,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = False,
    signature_alg_id: Optional[rfc5280.AlgorithmIdentifier] = None,
) -> rfc5755.AttributeCertificate:
    """Build and sign an AttributeCertificate from an AttCertTemplate."""
    signature_alg_id = signature_alg_id or prepare_alg_ids.prepare_sig_alg_id(
        signing_key=signing_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
    )
    info = _build_attribute_cert_info_from_template(template, signature_alg_id, ca_cert=ca_cert)
    signature = protectionutils.sign_data_with_alg_id(
        alg_id=signature_alg_id,
        data=asn1utils.encode_to_der(info),
        key=signing_key,
    )

    cert = rfc5755.AttributeCertificate()
    cert["acinfo"] = info
    cert["signatureAlgorithm"] = signature_alg_id
    cert["signatureValue"] = univ.BitString.fromOctetString(signature)
    return cert


@not_keyword
def validate_attribute_cert_issuer_field(attr_cert: Union[rfc5755.AttributeCertificate, rfc5755.AttCertIssuer]) -> None:
    """Validate the issuer field of an RFC 5755 `AttributeCertificate`.

    :param attr_cert: The AttributeCertificate or AttCertIssuer structure to validate.
    :raises BadCertTemplate: If the issuer field is not present or empty or not correct in `v2Form`.
    """
    if isinstance(attr_cert, rfc5755.AttributeCertificate):
        if attr_cert["acinfo"]["issuer"].isValue:
            raise BadAttributeCert("Issuer field of AttributeCertificate MUST NOT be present.")
        att_cert_issuer = attr_cert["acinfo"]["issuer"]
    else:
        if not attr_cert.isValue:
            raise BadAttributeCert("Issuer field of AttributeCertificate MUST be present.")
        att_cert_issuer = attr_cert

    if att_cert_issuer.getName() != "v2Form":
        raise BadAttributeCert("Issuer field of AttributeCertificate MUST use v2Form.")

    v2form = att_cert_issuer["v2Form"]
    if not v2form["issuerName"].isValue:
        raise BadAttributeCert("IssuerSerial field of AttributeCertificate MUST be present.")

    if v2form["baseCertificateID"].isValue:
        raise BadAttributeCert(
            "baseCertificateID field of v2Form, inside the AttributeCertificate MUST NOT be present."
        )

    if v2form["objectDigestInfo"].isValue:
        raise BadAttributeCert("objectDigestInfo field of v2Form, inside the AttributeCertificate MUST NOT be present.")


def _validate_attr_holder(holder: rfc5755.Holder) -> None:
    """Validate an RFC 5755 `Holder` structure."""
    if holder["objectDigestInfo"].isValue:
        if int(holder["objectDigestInfo"]["digestedObjectType"]) == 2:
            raise BadAttributeCert(
                "An AttributeCertificate MUST not use otherObjectTypes "
                "inside the `objectDigestInfo` field for the holder structure."
            )


def _validate_attr_cert_validity_period(attr_cert_validity: rfc5755.AttCertValidityPeriod) -> None:
    """Validate the validity period of an RFC 5755 `AttributeCertificateInfo` structure."""
    now = datetime.now(tz=timezone.utc)

    not_before = attr_cert_validity["notBeforeTime"].asDateTime
    not_after = attr_cert_validity["notAfterTime"].asDateTime

    if now < not_before:
        raise BadAttributeCert(
            f"AttributeCertificate is not yet valid. NotBeforeTime: {not_before.isoformat()}, "
            f"current time: {now.isoformat()}."
        )

    if now > not_after:
        raise BadAttributeCert(
            f"AttributeCertificate has expired. NotAfterTime: {not_after.isoformat()}, current time: {now.isoformat()}."
        )


@keyword("Validate AttributeCertificate")
def validate_attribute_cert(attr_cert: rfc5755.AttributeCertificate) -> None:
    """Validate an RFC 5755 `AttCertTemplate` structure."""
    ac_info: rfc5755.AttributeCertificateInfo = attr_cert["acinfo"]
    if int(ac_info["version"]) != 1:
        raise BadAttributeCert(
            f"Invalid version number for the AttributeCertificate: {int(ac_info['version'])}. "
            f"Only version 1 is supported."
        )

    _validate_attr_holder(ac_info["holder"])
    validate_attribute_cert_issuer_field(attr_cert)
    _validate_attr_cert_validity_period(ac_info["attrCertValidityPeriod"])


def validate_issuer_ser_against_cert(cert: rfc9480.CMPCertificate, issuer_ser: rfc5755.IssuerSerial) -> None:
    """Validate an RFC 4212 `IssuerSerial` structure against a CMPCertificate.

    :param cert: The CMPCertificate to validate the IssuerSerial against.
    :param issuer_ser: The IssuerSerial structure to validate.
    """
    if issuer_ser["issuerUID"].isValue:
        uid = cert["tbsCertificate"]["issuerUniqueID"]
        if not uid.isValue or uid.asOctets() != issuer_ser["issuerUID"].asOctets():
            raise BadRequest(
                f"Invalid issuerUID in IssuerSerial: expected {uid.asOctets().hex() if uid.isValue else None}, "
                f"got {issuer_ser['issuerUID'].asOctets().hex()}."
            )

    for i, name in enumerate(issuer_ser["issuer"]):
        if not compareutils.compare_general_name_and_name(name, cert["tbsCertificate"]["issuer"]):
            raise BadRequest(
                f"Invalid issuer in IssuerSerial at index={i}: "
                f"expected {name.prettyPrint()}, "
                f"got {cert['tbsCertificate']['issuer'][i].prettyPrint()}."
            )

    if cert["tbsCertificate"]["serialNumber"] != issuer_ser["serial"]:
        raise BadRequest(
            f"Invalid serial number in IssuerSerial: "
            f"expected {cert['tbsCertificate']['serialNumber']}, "
            f"got {issuer_ser['serial']}."
        )


@not_keyword
def find_cert_from_issuer_serial(
    certs: Sequence[rfc9480.CMPCertificate],
    issuer_ser: rfc5755.IssuerSerial,
) -> Optional[rfc9480.CMPCertificate]:
    """Find a CMPCertificate from a sequence by matching an RFC 4212 `IssuerSerial` structure.

    :param certs: The sequence of CMPCertificates to search.
    :param issuer_ser: The IssuerSerial structure to match.
    :return: The matching CMPCertificate, or `None` if not found.
    """
    der_data = asn1utils.encode_to_der(issuer_ser)
    for cert in certs:
        cert_issuer_ser = prepare_issuer_serial_from_cert(cert)
        der_cert_issuer_ser = asn1utils.encode_to_der(cert_issuer_ser)
        if der_data == der_cert_issuer_ser:
            return cert
    return None


@not_keyword
def find_cert_from_general_names_structure(
    certs: Sequence[rfc9480.CMPCertificate], issuer_name: rfc9480.GeneralNames
) -> Optional[rfc9480.CMPCertificate]:
    """Find a CMPCertificate from a sequence by matching its issuer name.

    :param certs: The sequence of CMPCertificates to search.
    :param issuer_name: The issuer name to match.
    """
    for cert in certs:
        for name in issuer_name:
            if compareutils.compare_general_name_and_name(name, cert["tbsCertificate"]["issuer"]):
                return cert
    return None


@not_keyword
def find_cert_from_object_digest_info(
    certs: Sequence[rfc9480.CMPCertificate],
    object_digest_info: rfc5755.ObjectDigestInfo,
) -> Optional[rfc9480.CMPCertificate]:
    """Find a CMPCertificate from a sequence by matching an RFC 4212 `ObjectDigestInfo` structure.

    :param certs: The sequence of CMPCertificates to search.
    :param object_digest_info: The ObjectDigestInfo structure to match.
    :return: The matching CMPCertificate, or `None` if not found.
    :raises BadAlg: If the digest algorithm is not supported.
    :raises BadRequest: If the object type is set, because it is not supported.
    """
    digest = object_digest_info["objectDigest"].asOctets()
    digest_obj_type = object_digest_info["digestedObjectType"]
    if digest_obj_type == 0:
        use_pub_key = True
    elif digest_obj_type == 1:
        use_pub_key = False
    else:
        other_oid = oid_mapping.may_return_oid_to_name(object_digest_info["otherObjectTypeID"])
        raise BadRequest(f"Not Implemented to compute the digest of the following object type: {other_oid}")

    for cert in certs:
        cert_der_data = _convert_cert_or_pub_key_to_der(cert, use_pub_key=use_pub_key)
        computed_digest = oid_mapping.compute_hash_from_alg_id(object_digest_info["digestAlgorithm"], cert_der_data)
        if computed_digest == digest:
            return cert
    return None


def _validate_holder_structure_same_cert(holder: rfc4212.Holder, cert: rfc9480.CMPCertificate) -> None:
    """Validate that a holder structure identifies the same certificate as the one provided.

    :param holder: The holder structure to validate.
    :param cert: The certificate to validate against.
    """
    err_msg = "The holder structure does not identify the same certificate as the one provided."

    try:
        if holder["baseCertificateID"].isValue:
            validate_issuer_ser_against_cert(cert, holder["baseCertificateID"])

        if holder["objectDigestInfo"].isValue:
            validate_object_digest_info(cert, holder["objectDigestInfo"])

        if holder["entityName"].isValue:
            if not find_cert_from_general_names_structure([cert], holder["entityName"]):
                raise BadRequest(f"Invalid entityName: {holder['entityName'].prettyPrint()}.")

    except BadRequest as e:
        raise BadRequest(err_msg, error_details=[e.message] + e.get_error_details()) from e


def validate_holder_structure(holder: rfc4212.Holder, issued_certs: Sequence[rfc9480.CMPCertificate]) -> None:
    """Validate an RFC 4212 `Holder` structure.

    :param holder: The `Holder` structure to validate.
    :param issued_certs: The sequence of issued certificates.
    """
    if holder["baseCertificateID"].isValue:
        cert = find_cert_from_issuer_serial(issued_certs, holder["baseCertificateID"])
        name_type = "baseCertificateID"

    elif holder["entityName"].isValue:
        cert = find_cert_from_general_names_structure(issued_certs, holder["entityName"])
        name_type = "entityName"

    elif holder["objectDigestInfo"].isValue:
        cert = find_cert_from_object_digest_info(issued_certs, holder["objectDigestInfo"])
        name_type = "objectDigestInfo"
    else:
        raise BadRequest(f"Invalid holder structure: {holder.prettyPrint()}.")

    if cert is None:
        raise BadRequest(f"Invalid `Holder` with type:{name_type}: {holder['name_type'].prettyPrint()}.")

    # Validate that the holder structure identifies the same certificate as the one found,
    # and not a different one across the structures.
    _validate_holder_structure_same_cert(holder, cert)
