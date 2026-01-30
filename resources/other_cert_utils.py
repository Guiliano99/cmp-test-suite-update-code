# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Helper for RFC 4212 alternative certificate formats, like an `AttributeCertificate` or an OpenPGP certificate."""

import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, Sequence, Union

from pyasn1.type import base, tag, univ
from pyasn1_alt_modules import rfc4211, rfc4212, rfc5280, rfc5755, rfc9480
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


def _prepare_optional_att_cert_validity(
    not_before_time: Optional[Union[str, float, datetime]] = None,
    not_after_time: Optional[Union[str, float, datetime]] = None,
) -> rfc4212.OptionalAttCertValidity:
    """Prepare an `OptionalAttCertValidity` structure.

    :param not_before_time: The notBeforeTime value.
    :param not_after_time: The notAfterTime value.
    :return: The populated `OptionalAttCertValidity` structure.
    """
    validity = rfc4212.OptionalAttCertValidity().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5)
    )
    if not_before_time is not None:
        validity["notBeforeTime"] = prepareutils.prepare_generalized_time(not_before_time).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
    if not_after_time is not None:
        validity["notAfterTime"] = prepareutils.prepare_generalized_time(not_after_time).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
    return validity


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


@not_keyword
def prepare_issuer_serial_from_cert(
    cert: rfc9480.CMPCertificate,
    target: Optional[rfc5755.IssuerSerial] = None,
) -> rfc5755.IssuerSerial:
    """Prepare an `IssuerSerial` structure from a CMPCertificate.

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


def prepare_holder(  # noqa: D417 undocumented params
    base_certificate_id: Optional[Union[rfc9480.CMPCertificate, rfc5755.IssuerSerial]] = None,
    entity_name: Optional[GeneralNamesType] = None,
    object_digest_info: Optional[rfc5755.ObjectDigestInfo] = None,
    target: Optional[rfc4212.Holder] = None,
) -> rfc4212.Holder:
    """Prepare a `Holder` structure for an attribute certificate.

    The `Holder` structure identifies the entity to which an Attribute Certificate is issued.
    It can identify the holder by a base certificate (using `IssuerSerial`), by name (`entityName`),
    or by the digest of an object (`ObjectDigestInfo`).

    Arguments:
    ---------
        - `base_certificate_id`: The baseCertificateID value (CMPCertificate or IssuerSerial). Defaults to `None`.
        - `entity_name`: The entityName value (GeneralNames). Defaults to `None`.
        - `object_digest_info`: The objectDigestInfo value. Defaults to `None`.
        - `target`: Optional `Holder` object to populate. Defaults to `None`.

    Returns:
    -------
        - The populated `Holder` structure.

    Examples:
    --------
    | ${holder} | Prepare Holder | base_certificate_id=${cert} |
    | ${holder} | Prepare Holder | entity_name=CN=John Doe | object_digest_info=${digest_info} |

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


@keyword(name="Prepare AttCertTemplate")
def prepare_att_cert_template(  # noqa: D417 undocumented params
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
    """Prepare an `AttCertTemplate` structure.

    This structure is used to specify the template for an Attribute Certificate
    request in CMP messages. All fields are optional, and if `not_before_time` and
    `not_after_time` are both `None`, the current time is used as the `not_before_time`.

    Arguments:
    ---------
        - `version`: The version number of the attribute certificate. Defaults to `None`.
        - `holder`: The holder of the attribute certificate. Defaults to `None`.
        - `issuer`: The issuer of the attribute certificate. Defaults to `None`.
        - `signature`: The signature algorithm identifier. Defaults to `None`.
        - `serial_number`: The serial number of the attribute certificate. Defaults to `None`.
        - `not_before_time`: The notBeforeTime value (str, float, or datetime). Defaults to `current time`
        if `not_after_time` after is also `None`.
        - `not_after_time`: The notAfterTime value (str, float, or datetime). Defaults to `None`.
        - `attributes`: A sequence of attributes. Defaults to `None`.
        - `issuer_unique_id`: The issuer unique identifier. Defaults to `None`.
        - `extensions`: The extensions of the attribute certificate. Defaults to `None`.
        - `target`: Optional `AttCertTemplate` object to populate. Defaults to `None`.

    Returns:
    -------
        - The populated `AttCertTemplate` structure.

    Examples:
    --------
    | ${template} | Prepare AttCertTemplate | version=1 | serial_number=12345 |
    | ${template} | Prepare AttCertTemplate | holder=${holder} | issuer=${issuer} | not_before_time=2026-01-01 |

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

    if not_before_time is None and not_after_time is None:
        not_before_time =  datetime.now(timezone.utc) - timedelta(seconds=3)

    if not_before_time is not None or not_after_time is not None:
        att_template["attrCertValidityPeriod"] = _prepare_optional_att_cert_validity(
            not_before_time=not_before_time,
            not_after_time=not_after_time,
        )
    if attributes is not None:
        attr_values = univ.SequenceOf(componentType=rfc4212.Attribute())  # type: ignore
        for entry in attributes:
            attr_values.append(entry)
        att_template["attributes"] = attr_values
    if issuer_unique_id is not None:
        att_template["issuerUniqueID"] = issuer_unique_id
    if extensions is not None:
        att_template["extensions"].extend(extensions)
    return att_template


def _patch_object_digest_info_to_structure(
    structure: rfc5755.V2Form, object_digest_info: Optional[rfc5755.ObjectDigestInfo] = None
) -> rfc5755.V2Form:
    """Patch an `AttCertIssuer` structure with an `ObjectDigestInfo` structure.

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
    """Patch an `AttCertIssuer` structure with a `V2Form` structure.

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


@keyword(name="Prepare AttCertIssuer V2Form")
def prepare_att_cert_issuer_v2form(  # noqa: D417 undocumented params
    ca_cert: rfc9480.CMPCertificate,
    add_base_certificate_id: bool = False,
    add_digest_obj_info: bool = False,
    hash_alg: str = "sha256",
    **kwargs,
) -> rfc5755.V2Form:
    """Prepare a `V2Form` structure for an attribute certificate issuer.

    This structure is used to specify the issuer information for an Attribute Certificate
    in version 2 format. The function populates the V2Form object with issuer details,
    including optional issuer serial information and object digest information.

    Arguments:
    ---------
        - `ca_cert`: Certificate authority (CA) certificate in the form of a CMPCertificate.
        - `add_base_certificate_id`: Boolean flag indicating whether to add the issuer's serial information in \
        the V2Form. Defaults to `False`.
        - `add_digest_obj_info`: Boolean flag specifying whether to include object digest information. \
        Defaults to `False`.
        - `hash_alg`: The hashing algorithm to use for object digest calculations. Defaults to "sha256".

    `**kwargs`: Optional keyword arguments that may include:
    ------------
            - `target`: A pre-constructed `V2Form` structure to be used as the base.
            - `issuer_name`: Specifies the issuer name override as an alternative to extracting from the \
            provided CA certificate.
            - `object_digest_info`: A pre-constructed `ObjectDigestInfo` structure to be included in the V2Form.

    Returns:
    -------
        - A populated `V2Form` structure containing all relevant issuer details.

    Examples:
    --------
    | ${v2form} | Prepare AttCertIssuer V2Form | ${ca_cert} |
    | ${v2form} | Prepare AttCertIssuer V2Form | ${ca_cert} | add_base_certificate_id=True | add_digest_obj_info=True |
    | ${v2form} | Prepare AttCertIssuer V2Form | ${ca_cert} | hash_alg=sha512 | issuer_name=CN=Custom CA |

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


@keyword(name="Prepare OpenPGPCertTemplateExtended")
def prepare_openpgp_cert_template_extended(  # noqa: D417 undocumented params
    native_template: Optional[bytes] = None,
    controls: Optional[rfc4211.Controls] = None,
    target: Optional[Union[rfc4212.OpenPGPCertTemplateExtended, bytes]] = None,
) -> rfc4212.OpenPGPCertTemplateExtended:
    """Prepare an `OpenPGPCertTemplateExtended` structure.

    Used to create or populate an OpenPGP certificate template structure to issue an OpenPGP
    certificate.

    Arguments:
    ---------
       - `native_template`: The native OpenPGP certificate template in bytes.
       - `controls`: Optional additional `Controls` for the openpgp certificate template.
       - `target`: Optional pre-constructed `OpenPGPCertTemplateExtended` structure or
       der encoded bytes to be used as the base.

    Returns:
    -------
       - The populated `OpenPGPCertTemplateExtended` structure.

    Raises:
    ------
       - `ValueError`: If both `native_template` and `target` are specified or if neither is specified.
       - `BadAsn1Data`: If the der encoded `target` is not decode-able

    Examples:
    --------
    | ${openpgp_cert_template} | Prepare OpenPGPCertTemplateExtended | native_template=${native_template_bytes} |
    | ${openpgp_cert_template} | Prepare OpenPGPCertTemplateExtended | target=${der_encoded_bytes} | \
    controls=${controls} |

    """
    if isinstance(target, bytes):
        data, rest = asn1utils.try_decode_pyasn1(target, rfc4212.OpenPGPCertTemplateExtended())  # type: ignore
        data: rfc4212.OpenPGPCertTemplateExtended
        if rest:
            logging.debug(
                "The trailing data has to be added inside the `prepare_alt_cert_template_cert_request` function."
            )
        return data

    if target is not None and controls is None:
        return target

    if native_template is not None and target is not None:
        raise ValueError("Cannot specify both `native_template` and `target` arguments.")

    if native_template is None and target is None:
        raise ValueError("Either `native_template` or `target` argument must be specified.")

    if target is None:
        target = rfc4212.OpenPGPCertTemplateExtended()
        target["nativeTemplate"] = rfc4212.OpenPGPCertTemplate(native_template)

    if controls is not None:
        target["controls"].extend(controls)

    return target


def _prepare_attr_type_and_value(
    attr_type: univ.ObjectIdentifier, attr_value: base.Asn1Item, bad_data: bool = False
) -> rfc4211.AttributeTypeAndValue:
    """Prepare an `AttributeTypeAndValue` structure from an attribute type and value.

    :param attr_type: The attribute type.
    :param attr_value: The attribute value.
    :param bad_data: Boolean flag indicating whether to include bad data in the attribute value. Defaults to False.
    """
    attr_entry = rfc4211.AttributeTypeAndValue()
    data = asn1utils.encode_to_der(attr_value)

    if bad_data:
        data += os.urandom(1)

    attr_entry["value"] = univ.Any(data)
    attr_entry["type"] = attr_type
    return attr_entry


@not_keyword
def prepare_alt_cert_template(
    other_format: Union[rfc4212.AttCertTemplate, rfc4212.OpenPGPCertTemplateExtended], bad_data: bool = False
) -> rfc4212.AltCertTemplate:
    """Prepare an `AltCertTemplate` structure for an empty certificate template.

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
    bad_controls_data: bool = False,
) -> rfc4211.CertRequest:
    """Prepare a `CertRequest` structure for a certificate request in another format than the CertTemplate.

    Arguments:
    ---------
       - `other_cert_format`: The other certificate format template.
       - `cert_req_id`: The certificate request ID. Defaults to `0`.
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
    | ${cert_request} | Prepare AltCertTemplate CertRequest | ${openpgp_cert_template} | cert_req_id=1 | True |

    """
    cert_request = rfc4211.CertRequest()

    attr_type_value = prepare_alt_cert_template(other_cert_format, bad_data=False)

    controls_entry = _prepare_attr_type_and_value(
        rfc4212.id_regCtrl_altCertTemplate, attr_type_value, bad_controls_data
    )

    cert_request["controls"].append(controls_entry)
    cert_request["certTemplate"] = rfc4211.CertTemplate()
    cert_request["certReqId"] = int(cert_req_id)
    return cert_request
