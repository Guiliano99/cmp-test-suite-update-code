# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Logic for building/validating Chameleon certificates/certification requests."""

import logging
from typing import List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc5652, rfc6402, rfc9480
from robot.api.deco import keyword, not_keyword

import resources.prepare_alg_ids
import resources.protectionutils
from pq_logic.hybrid_structures import (
    DeltaCertificateDescriptor,
    DeltaCertificateRequestSignatureValue,
    DeltaCertificateRequestValue,
)
from pq_logic.tmp_oids import (
    id_at_deltaCertificateRequest,
    id_at_deltaCertificateRequestSignature,
    id_ce_deltaCertificateDescriptor,
)
from resources import (
    certbuildutils,
    certextractutils,
    certutils,
    compareutils,
    convertutils,
    cryptoutils,
    keyutils,
    prepareutils,
    utils,
)
from resources.asn1utils import try_decode_pyasn1
from resources.certextractutils import get_extension
from resources.convertutils import (
    copy_asn1_certificate,
    subject_public_key_info_from_pubkey,
)
from resources.copyasn1utils import copy_csr, copy_name, copy_validity
from resources.exceptions import BadAltPOP, BadAsn1Data, BadCertTemplate
from resources.oid_mapping import get_hash_from_oid
from resources.typingutils import PublicKey, SignKey, VerifyKey


def _prepare_issuer_and_subject(
    dcd: DeltaCertificateDescriptor, delta_cert: rfc9480.CMPCertificate, base_cert: rfc9480.CMPCertificate
):
    """Prepare the issuer and subject fields for the DCD extension, add them, if they differ.

    :param dcd: The `DeltaCertificateDescriptor` to populate.
    :param delta_cert: Parsed Delta Certificate structure.
    :param base_cert: Parsed Base Certificate structure.
    :return: The may updated `DeltaCertificateDescriptor` structure.
    """
    if not compareutils.compare_pyasn1_names(
        delta_cert["tbsCertificate"]["issuer"], base_cert["tbsCertificate"]["issuer"]
    ):
        issuer_obj = rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
        issuer = copy_name(filled_name=delta_cert["tbsCertificate"]["issuer"], target=issuer_obj)
        dcd["issuer"] = issuer

    if not compareutils.compare_pyasn1_names(
        delta_cert["tbsCertificate"]["subject"], base_cert["tbsCertificate"]["subject"]
    ):
        subject_obj = rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
        subject = copy_name(filled_name=delta_cert["tbsCertificate"]["subject"], target=subject_obj)
        dcd["subject"] = subject

    return dcd


def _compare_times(time1: rfc5280.Time, time2: rfc5280.Time) -> bool:
    """Compare two `rfc5280.Time` objects.

    :param time1: The first `rfc5280.Time` object.
    :param time2: The second `rfc5280.Time` object.
    :return: True if the times are equal, False otherwise.
    """
    return encoder.encode(time1) == encoder.encode(time2)


@not_keyword
def prepare_dcd_extension_from_delta(delta_cert: rfc9480.CMPCertificate, base_cert: rfc9480.CMPCertificate):
    """Prepare a Delta Certificate Descriptor (DCD) extension from a parsed Delta Certificate and Base Certificate.

    Fields:
    - `serialNumber`: Serial number of the Delta Certificate.
    - `signature`: Algorithm used for signing the Delta Certificate (if it differs from the Base Certificate).
    - `issuer`: Distinguished name of the issuer in the Delta Certificate (if it differs from the Base Certificate).
    - `validity`: Validity period of the Delta Certificate (if it differs from the Base Certificate).
    - `subject`: Subject name of the Delta Certificate (if it differs from the Base Certificate).
    - `subjectPublicKeyInfo`: Public key information specific to the Delta Certificate (cannot be the same key).
    - `extensions`: List of extensions that differ between the Delta and Base Certificates.
    - `signatureValue`: Signature of the Delta Certificate.

    :param delta_cert: Parsed Delta Certificate structure.
    :param base_cert: Parsed Base Certificate structure.
    :return: A DeltaCertificateDescriptor instance.
    """
    dcd = DeltaCertificateDescriptor()

    dcd["serialNumber"] = delta_cert["tbsCertificate"]["serialNumber"]

    same_alg_id = compareutils.compare_alg_id_without_tag(
        delta_cert["tbsCertificate"]["signature"], base_cert["tbsCertificate"]["signature"]
    )

    if not same_alg_id:
        dcd["signature"]["algorithm"] = delta_cert["tbsCertificate"]["signature"]["algorithm"]

    dcd = _prepare_issuer_and_subject(
        dcd=dcd,
        delta_cert=delta_cert,
        base_cert=base_cert,
    )

    if not _compare_times(delta_cert["tbsCertificate"]["validity"], base_cert["tbsCertificate"]["validity"]):
        validity2 = rfc5280.Validity().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
        dcd["validity"] = copy_validity(delta_cert["tbsCertificate"]["validity"], target=validity2)

    dcd["subjectPublicKeyInfo"] = delta_cert["tbsCertificate"]["subjectPublicKeyInfo"]

    # Include differing extensions, if any
    differing_extensions = _clean_base_and_delta_extensions(
        base_cert["tbsCertificate"]["extensions"], delta_cert["tbsCertificate"]["extensions"]
    )
    logging.debug("Differing extensions: %s", differing_extensions.prettyPrint())
    if differing_extensions.isValue:
        dcd["extensions"].extend(differing_extensions)

    dcd["signatureValue"] = delta_cert["signature"]

    return dcd


def _prepare_dcd_extensions(
    delta_certificate: rfc9480.CMPCertificate,
    base_certificate: rfc9480.CMPCertificate,
    exclude_extensions: bool = False,
) -> List[rfc5280.Extension]:
    """Prepare the `Extensions` field of the DCD extension by comparing the Base and Delta Certificate.

    :param delta_certificate: Parsed Delta Certificate structure.
    :param base_certificate: Parsed Base Certificate structure.
    :return: A list of differing extensions.
    """
    if exclude_extensions:
        return []

    base_extensions = {ext["extnID"]: ext for ext in base_certificate["tbsCertificate"]["extensions"]}
    delta_extensions = {ext["extnID"]: ext for ext in delta_certificate["tbsCertificate"]["extensions"]}

    """
    If the extensions field is absent, then all extensions in the Delta Certificate 
    MUST have the same criticality and DER-encoded value as the Base Certificate 
    (except for the DCD extension, which MUST be absent from the Delta Certificate)
    """  # noqa: W291 Trailing whitespace

    differing_extensions = []
    for ext_id, ext in delta_extensions.items():
        if ext_id == id_ce_deltaCertificateDescriptor:
            continue  # Skip the DCD extension itself

        if ext_id not in base_extensions:
            differing_extensions.append(ext)
        elif base_extensions.get(ext_id) is not None:
            if encoder.encode(base_extensions[ext_id]) == encoder.encode(ext):
                differing_extensions.append(ext)

    # Ensure no invalid extensions are included
    #  pass

    return differing_extensions


### as of Section 4.2. Issuing a Base Certificate


@not_keyword
def build_chameleon_base_certificate(
    delta_cert: rfc9480.CMPCertificate,
    base_tbs_cert: rfc5280.TBSCertificate,
    ca_key: SignKey,
    use_rsa_pss: bool = False,
    critical: bool = False,
    hash_alg: Optional[str] = None,
    bad_sig: bool = False,
) -> rfc9480.CMPCertificate:
    """Issue a Base Certificate with the DeltaCertificateDescriptor (DCD) extension.

    :param delta_cert: Parsed Delta Certificate.
    :param base_tbs_cert: `TBSCertificate` structure for the certificate to be issued.
    :param ca_key: Private key of the CA for signing the Base Certificate.
    :param use_rsa_pss: Whether to use PSS-padding for signing. Defaults to `False`.
    :param critical: Whether the DCD extension is critical. Defaults to `False`.
    :param hash_alg: The hash algorithm used for signing the Paired Certificate (e.g., 'sha256').
    (if not provided, it will be extracted from the Delta Certificate).
    :param bad_sig: Whether to make the signature invalid. Defaults to `False`.
    :return: A fully signed Base Certificate structure.
    """
    # As of Section 4 Note:
    # The inclusion of the DCD extension within a Base Certificate is not a statement from the
    # issuing Certification Authority of the Base Certificate that the contents of the Delta
    # Certificate have been verified.

    # The Delta Certificate will necessarily need to be issued prior
    # to the issuance of the Base Certificate.

    # To simplify reconstruction of the Delta Certificate, the signatures for Base and Delta Certificates
    # MUST be calculated over the DER encoding of the TBSCertificate structure.

    # Some features are Policy dependent: For example, a policy may require that the
    # validity periods of the Base Certificate and Delta Certificate be identical, or that if the
    # Delta Certificate is revoked, the Base Certificate must also be revoked.

    hash_alg = hash_alg or get_hash_from_oid(delta_cert["tbsCertificate"]["signature"]["algorithm"], only_hash=True)

    base_cert = rfc9480.CMPCertificate()
    base_cert["tbsCertificate"] = base_tbs_cert

    dcd = prepare_dcd_extension_from_delta(delta_cert=delta_cert, base_cert=base_cert)

    dcd_extension = rfc5280.Extension()
    dcd_extension["extnID"] = id_ce_deltaCertificateDescriptor
    dcd_extension["critical"] = critical
    dcd_extension["extnValue"] = univ.OctetString(encoder.encode(dcd))
    base_tbs_cert["extensions"].append(dcd_extension)

    base_cert = rfc9480.CMPCertificate()
    base_cert["tbsCertificate"] = base_tbs_cert
    base_cert = certbuildutils.sign_cert(
        cert=base_cert, signing_key=ca_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss, bad_sig=bad_sig
    )
    return base_cert


# TODO add unit tests


@keyword(name="Validate DCD Extension")
def validate_dcd_extension(  # noqa: D417 Missing argument descriptions in the docstring
    dcd_extensions: Union[rfc5280.Extensions, rfc9480.CMPCertificate], base_cert_extensions: rfc5280.Extensions
) -> None:
    """Validate the DCD extension to ensure it meets the defined constraints.

    Arguments:
    ---------
        - `dcd_extensions`: Extensions contained in the DCD or the Paired Certificate.
        - `base_cert_extensions`: Extensions contained in the Base Certificate.

    Raises:
    ------
        - `ValueError`: If any invalid extension is detected in the DCD.
        - `BadAsn1Data`: If the DCD is not a valid `DeltaCertificateDescriptor`.

    Examples:
    --------
    | Validate DCD Extension | ${dcd_extensions} | ${base_cert_extensions} |

    """
    if isinstance(dcd_extensions, rfc9480.CMPCertificate):
        tmp_extn = get_extension(dcd_extensions["tbsCertificate"]["extensions"], id_ce_deltaCertificateDescriptor)
        data, _ = try_decode_pyasn1(tmp_extn["extnValue"], DeltaCertificateDescriptor())  # type: ignore
        data: DeltaCertificateDescriptor
        dcd_extensions = data["extensions"]

    base_cert_ext_map = {ext["extnID"]: ext for ext in base_cert_extensions}

    for dcd_ext in dcd_extensions:
        ext_id = dcd_ext["extnID"]

        # Step 1: DCD MUST NOT contain the extension if it matches Base Certificate's criticality + value
        if ext_id in base_cert_ext_map:
            base_ext = base_cert_ext_map[ext_id]
            if (
                dcd_ext["critical"] == base_ext["critical"]
                and dcd_ext["extnValue"].asOctets() == base_ext["extnValue"].asOctets()
            ):
                raise ValueError(
                    f"Invalid extension in DCD: Extension with ID {ext_id} is identical to one in the Base Certificate."
                )

        # Step 2: DCD MUST NOT contain extensions whose type does not appear in the Base Certificate
        # (i.e., extnID is not in the Base Certificate's extensions and is not the DCD extension type)
        if ext_id not in base_cert_ext_map and ext_id != id_ce_deltaCertificateDescriptor:
            raise ValueError(
                f"Invalid extension in DCD: Extension with ID {ext_id} is not present in the Base Certificate."
            )

        # Step 3: DCD MUST NOT contain an extension of the DCD type (recursive DCD extensions are forbidden)
        if ext_id == id_ce_deltaCertificateDescriptor:
            raise ValueError(f"Invalid extension in DCD: Recursive DCD extensions (ID {ext_id}) are not allowed.")


#################
# CSR
#################


@not_keyword
def prepare_delta_cert_req(
    signing_key: SignKey,
    delta_common_name: Optional[str] = None,
    extensions: Optional[rfc5280.Extensions] = None,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = False,
    omit_sig_alg_id: bool = False,
) -> DeltaCertificateRequestValue:
    """Prepare a `DeltaCertificateRequestValue` structure.

    :param signing_key: The private key of the Delta Certificate.
    :param delta_common_name: The subject name of the Delta Certificate (in openssl notation, e.g.,
    "CN=Hans Mustermann"). Defaults to `None`.
    :param extensions: The extensions for the Delta Certificate. Defaults to `None`.
    :param hash_alg: The hash algorithm used for signing. Defaults to "sha256".
    :param use_rsa_pss: Whether to use PSS-padding for signing. Defaults to `False`.
    :param omit_sig_alg_id: Whether to omit the signature algorithm ID. Defaults to `False`.
    :return: The populated `DeltaCertificateRequestValue` structure.
    """
    if not signing_key:
        raise ValueError("The delta value private key was not provided.")

    delta_req = DeltaCertificateRequestValue()

    if delta_common_name:
        name = rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        parsed_name = prepareutils.prepare_name(delta_common_name, target=name)
        delta_req["subject"] = parsed_name

    delta_req["subjectPKInfo"] = subject_public_key_info_from_pubkey(signing_key.public_key())

    if extensions is not None:
        delta_req["extensions"].extend(extensions)

    if not omit_sig_alg_id:
        sig_alg_id = resources.prepare_alg_ids.prepare_sig_alg_id(
            signing_key=signing_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss
        )
        alg_id = rfc5280.AlgorithmIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
        )

        alg_id["algorithm"] = sig_alg_id["algorithm"]
        alg_id["parameters"] = sig_alg_id["parameters"]

        delta_req["signatureAlgorithm"] = alg_id

    return delta_req


@keyword(name="Build Paired CSR")
def build_paired_csr(  # noqa: D417 Missing argument descriptions in the docstring
    base_private_key: SignKey,
    delta_private_key: SignKey,
    base_common_name: Union[str, rfc9480.Name] = "CN=Hans Mustermann",
    base_extensions: Optional[rfc5280.Extensions] = None,
    delta_extensions: Optional[rfc5280.Extensions] = None,
    **kwargs,
) -> rfc6402.CertificationRequest:
    """Create a paired CSR for a Base and Delta Certificate request.

    Arguments:
    ---------
        - `base_private_key`: Private key for signing the Base CSR.
        - `delta_private_key`: Private key for signing the `DeltaCertificateRequestValue`.
        - `base_common_name`: Subject of the Base Certificate. Defaults to "CN=Hans Mustermann".
        - `base_extensions`: Extensions for the Base Certificate. Defaults to `None`.
        - `delta_extensions`: Extensions for the Delta Certificate. Defaults to `None`.

    **kwargs:
    --------
        - `delta_common_name` (str): Subject of the Delta Certificate (in openssl notation, e.g., "CN=Hans Mustermann").
        Defaults to `None`.
        - `hash_alg`: The hash algorithm used for signing. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use PSS-padding for signing. Defaults to `False`.
        - `bad_alt_pop`: Whether to make the secondary signature invalid. Defaults to `False`.

    Returns:
    -------
        - The paired Certification Request.

    Examples:
    --------
    | ${csr}= | Build Paired CSR | ${base_private_key} | ${delta_private_key} | ${base_common_name} |
    | ${csr}= | Build Paired CSR | ${base_private_key} | ${delta_private_key} | ${base_common_name} | use_rsa_pss=True |

    """
    use_rsa_pss = kwargs.get("use_rsa_pss", False)
    hash_alg = kwargs.get("hash_alg", "sha256")

    # Step 1: Build certificationRequestInfo
    base_csr = certbuildutils.build_csr(
        signing_key=base_private_key,
        extensions=base_extensions,
        common_name=base_common_name,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        exclude_signature=True,
    )

    # Step 2: Prepare attribute.
    delta_request = prepare_delta_cert_req(
        signing_key=delta_private_key,
        extensions=delta_extensions,
        delta_common_name=kwargs.get("delta_common_name"),
        use_rsa_pss=use_rsa_pss,
        hash_alg=hash_alg,
    )

    # Step 3: Add attribute.
    delta_cert_attr = certbuildutils.prepare_single_value_attr(id_at_deltaCertificateRequest, delta_request)
    base_csr["certificationRequestInfo"]["attributes"].append(delta_cert_attr)

    # Step 4: Sign the CertificationRequestInfo using the private key of the Delta Certificate
    # request subject
    tmp_der_data = encoder.encode(base_csr["certificationRequestInfo"])
    delta_signature = cryptoutils.sign_data(
        data=tmp_der_data, key=delta_private_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss
    )

    if kwargs.get("bad_alt_pop"):
        delta_signature = utils.manipulate_first_byte(delta_signature)

    # Step 5: Prepare
    delta_sig_attr = certbuildutils.prepare_single_value_attr(
        id_at_deltaCertificateRequestSignature, DeltaCertificateRequestSignatureValue.fromOctetString(delta_signature)
    )

    # Step 6: Add attribute.
    base_csr["certificationRequestInfo"]["attributes"].append(delta_sig_attr)

    # Step 7: Sign.
    base_csr_info = encoder.encode(base_csr["certificationRequestInfo"])
    base_signature = cryptoutils.sign_data(
        data=base_csr_info, key=base_private_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg
    )

    base_csr["signatureAlgorithm"] = resources.prepare_alg_ids.prepare_sig_alg_id(
        signing_key=base_private_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss
    )

    base_csr["signature"] = univ.BitString.fromOctetString(base_signature)

    base_csr, _ = decoder.decode(encoder.encode(base_csr), rfc6402.CertificationRequest())

    return base_csr


###################
# Server side
###################


@not_keyword
def load_chameleon_csr_delta_key_and_sender(csr: rfc6402.CertificationRequest) -> Tuple[PublicKey, rfc9480.Name]:
    """Load the public key and sender from the `DeltaCertificateRequestValue`.

    :param csr: The `CertificationRequest` to extract the public key from.
    :return: The public key of the Delta Certificate request.
    :raises: ValueError: If the Delta Certificate request attribute is missing.
    :raises: InvalidKeyData: If the public key is not a valid key.
    """
    delta_req = None
    for attr in csr["certificationRequestInfo"]["attributes"]:
        if attr["attrType"] == id_at_deltaCertificateRequest:
            delta_req = decoder.decode(attr["attrValues"][0], asn1Spec=DeltaCertificateRequestValue())[0]
            break

    if delta_req is None:
        raise ValueError("`DeltaCertificateRequestValue` attribute is missing.")

    if not delta_req["subject"].isValue:
        sender = csr["certificationRequestInfo"]["subject"]
    else:
        target = rfc9480.Name()
        sender = copy_name(filled_name=delta_req["subject"], target=target)

    return keyutils.load_public_key_from_spki(delta_req["subjectPKInfo"]), sender


@not_keyword
def extract_chameleon_attributes(
    csr: rfc6402.CertificationRequest,
) -> Tuple[List[rfc5652.Attribute], DeltaCertificateRequestValue, DeltaCertificateRequestSignatureValue]:
    """
    Extract attributes from the CSR, excluding the signature attribute.

    :param csr: The `CertificationRequest` to extract attributes from.
    :return: A tuple containing:
        - All attributes except the signature one.
        - The Delta Certificate Request attribute.
        - The Delta Certificate Request Signature attribute.
    """
    non_signature_attributes = []
    delta_cert_request = None
    delta_cert_request_signature = None

    attributes = csr["certificationRequestInfo"]["attributes"]

    for attr in attributes:
        if attr["attrType"] == id_at_deltaCertificateRequest:
            delta_cert_request = decoder.decode(attr["attrValues"][0], asn1Spec=DeltaCertificateRequestValue())[0]
            non_signature_attributes.append(attr)
        elif attr["attrType"] == id_at_deltaCertificateRequestSignature:
            delta_cert_request_signature = decoder.decode(
                attr["attrValues"][0], asn1Spec=DeltaCertificateRequestSignatureValue()
            )[0]

        else:
            non_signature_attributes.append(attr)

    return non_signature_attributes, delta_cert_request, delta_cert_request_signature  # type: ignore


@keyword(name="Verify Paired CSR Signature")
def verify_paired_csr_signature(  # noqa: D417 Missing argument description in the docstring
    csr: rfc6402.CertificationRequest,
) -> DeltaCertificateRequestValue:
    """Verify the signature of a paired CSR.

    Arguments:
    ---------
       - `csr`: The `CertificationRequest` to verify.

    Returns:
    -------
         - The Delta Certificate Request attribute.

    Raises:
    ------
        - `ValueError`: If the Delta Certificate Request attribute is missing.
        - `BadPOP`: If the POP signature is invalid.
        - `BadAltPOP`: If the delta POP signature is invalid.

    Examples:
    --------
    | ${delta_req}= | Verify Paired CSR Signature | ${csr} |

    """
    csr_tmp = copy_csr(csr)

    certutils.verify_csr_signature(csr=csr_tmp)
    attributes, delta_req, delta_sig = extract_chameleon_attributes(csr=csr_tmp)

    if delta_req is None:
        raise ValueError("Delta Certificate Request attribute is missing.")
    if delta_sig is None:
        raise ValueError("Delta Certificate Request Signature attribute is missing.")

    # Step 3: Remove the Delta Certificate request signature attribute
    # from the CertificationRequest template
    attr = univ.SetOf(componentType=rfc5652.Attribute()).subtype(  # type: ignore
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )

    attr.extend(attributes)
    csr_tmp["certificationRequestInfo"]["attributes"] = attr
    if delta_req["signatureAlgorithm"].isValue:
        sig_alg_id = delta_req["signatureAlgorithm"]
    else:
        sig_alg_id = csr_tmp["signatureAlgorithm"]

    if not delta_req["subjectPKInfo"].isValue:
        raise ValueError("Delta Certificate Request 'subjectPKInfo' is missing.")

    public_key = keyutils.load_public_key_from_spki(delta_req["subjectPKInfo"])

    data = encoder.encode(csr_tmp["certificationRequestInfo"])

    try:
        public_key = convertutils.ensure_is_verify_key(public_key)
        resources.protectionutils.verify_signature_with_alg_id(
            alg_id=sig_alg_id, data=data, public_key=public_key, signature=delta_sig.asOctets()
        )
    except ValueError as e:
        raise BadCertTemplate("Public key mismatch was invalid or not a verify key.") from e

    except InvalidSignature:
        raise BadAltPOP("The chameleon alternative signature is invalid.")  # pylint: disable=raise-missing-from

    return delta_req


@not_keyword
def build_delta_cert(
    csr: rfc6402.CertificationRequest,
    delta_value: DeltaCertificateRequestValue,
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    alt_sign_key: Optional[SignKey] = None,
    **kwargs,
) -> rfc9480.CMPCertificate:
    """Prepare a Delta Certificate from a paired CSR.

    Extract necessary information from the CSR and build a Delta Certificate with its own values
    or the values from the CSR.

    :param csr: The paired CSR.
    :param delta_value: The `DeltaCertificateRequestValue` object extracted from the CSR.
    :param ca_key: The CA key for signing the certificate.
    :param ca_cert: The CA certificate matching the CA key.
    :param alt_sign_key: An alternative signing key for the certificate. Defaults to `None`.
    :return: The populated `TBSCertificate` structure.
    """
    csr_tmp = rfc6402.CertificationRequest()

    if delta_value["subject"].isValue:
        csr_tmp["certificationRequestInfo"]["subject"] = delta_value["subject"]
    else:
        csr_tmp["certificationRequestInfo"]["subject"] = csr["certificationRequestInfo"]["subject"]

    csr_tmp["certificationRequestInfo"]["subjectPublicKeyInfo"] = delta_value["subjectPKInfo"]

    if delta_value["extensions"].isValue and kwargs.get("include_delta_extensions", True):
        csr_tmp = certbuildutils.csr_add_extensions(
            csr_tmp,
            delta_value["extensions"],
        )

    return certbuildutils.build_cert_from_csr(
        csr=csr_tmp,
        ca_key=ca_key,
        ca_cert=ca_cert,
        alt_sign_key=alt_sign_key,
        hash_alg=kwargs.get("hash_alg", "sha256"),
        use_rsa_pss=kwargs.get("use_rsa_pss", False),
        include_ski=kwargs.get("include_ski", True),
        extensions=kwargs.get("extensions"),
        include_csr_extensions=kwargs.get("include_csr_extensions", False),
        validity=kwargs.get("validity"),
    )


def _validate_keys(
    first_key: PublicKey,
    delta_key: PublicKey,
    min_key_size: int = 2048,
    max_key_size: int = 8192,
) -> None:
    """Validate the keys used for the Base and Delta Certificates.

    :param first_key: The public key of the Base Certificate.
    :param delta_key: The public key of the Delta Certificate.
    :raises ValueError: If the keys are not compatible.
    """
    if not isinstance(first_key, VerifyKey):
        raise BadCertTemplate(f"Base Certificate public key is not a verifying key.Got {type(first_key)} instead.")

    if not isinstance(delta_key, VerifyKey):
        raise BadCertTemplate(f"Delta Certificate public key is not a verifying key.Got {type(delta_key)} instead.")

    if delta_key == first_key:
        raise BadCertTemplate("Delta Certificate public key must not match the Base Certificate public key.")

    if isinstance(delta_key, RSAPublicKey):
        key_size = delta_key.key_size
        if key_size < min_key_size or key_size > max_key_size:
            raise BadCertTemplate(
                f"Delta Certificate public key size {key_size} is not within the "
                f"allowed range ({min_key_size}-{max_key_size})."
            )

    if isinstance(first_key, RSAPublicKey):
        key_size = first_key.key_size
        if key_size < min_key_size or key_size > max_key_size:
            raise BadCertTemplate(
                f"Base Certificate public key size {key_size} is not within the "
                f"allowed range ({min_key_size}-{max_key_size})."
            )


def _parse_extension(
    csr: Union[rfc6402.CertificationRequest, DeltaCertificateRequestValue],
    target_extensions: rfc9480.Extensions,
    include_ski: Optional[bool] = True,
    ski_critical: bool = False,
) -> rfc9480.Extensions:
    """Parse the extension and copy it to the target.

    :param csr: The `CSR` or `DeltaCertificateRequestValue` to parse.
    :param target_extensions: The target extensions to copy to.
    :param include_ski: Whether to include the Subject Key Identifier (SKI) extension, if `None` it will be included,
    if it is present in the `csr`. Defaults to `True`.
    :param ski_critical: Whether the SKI extension is critical.
    :return: The target extensions with the parsed extensions.
    """
    csr_extension, spki = certbuildutils.parse_extension_and_public_key(csr)

    is_base = isinstance(csr, rfc6402.CertificationRequest)

    if csr_extension is None:
        return target_extensions

    ski, _ = certbuildutils.validate_subject_key_identifier_extension(csr, prepare_extn=include_ski is True)
    if ski is not None and include_ski in [True, None]:
        target_extensions.append(ski)
    elif ski is not None:
        public_key = keyutils.load_public_key_from_spki(spki)
        ski = certbuildutils.prepare_ski_extension(key=public_key, critical=ski_critical)
        target_extensions.append(ski)

    for x in csr_extension:
        if x["extnID"] == id_ce_deltaCertificateDescriptor:
            msg = "DeltaCertificateRequestValue" if not is_base else "Base CSR"
            raise BadCertTemplate(f"DeltaCertificateDescriptor extension is not allowed in the {msg}.")

        if x["extnID"] == rfc5280.id_ce_subjectKeyIdentifier:
            continue

        if not certbuildutils.extensions_contains_extn_id(x["extnID"], target_extensions):  # type: ignore
            target_extensions.append(x)

    return target_extensions


def _process_remove_extensions(
    csr: rfc6402.CertificationRequest,
    delta_req_value: DeltaCertificateRequestValue,
    oids: List[univ.ObjectIdentifier],
    include_ski: Optional[bool] = None,
    ski_critical: bool = False,
    additional_extensions: Optional[rfc9480.Extensions] = None,
) -> Tuple[rfc9480.Extensions, rfc9480.Extensions]:
    """Remove the extensions from the CSR and Delta Certificate."""
    base_extensions = rfc9480.Extensions()
    delta_extensions = rfc9480.Extensions()

    if additional_extensions is None:
        additional_extensions = rfc9480.Extensions()

    csr_extensions, _ = certbuildutils.parse_extension_and_public_key(csr)

    if csr_extensions is None:
        raise ValueError("CSR extensions are missing. This function should not be called.")

    csr_ski, _ = certbuildutils.validate_subject_key_identifier_extension(csr, prepare_extn=include_ski in [True, None])
    delta_ski, _ = certbuildutils.validate_subject_key_identifier_extension(
        delta_req_value, critical=ski_critical, prepare_extn=include_ski in [True, None]
    )
    if include_ski in [None, True]:
        base_extensions.append(csr_ski)

    if include_ski in [None, True]:
        delta_extensions.append(delta_ski)

    base_extensions.extend(additional_extensions)
    delta_extensions.extend(additional_extensions)

    for oid in oids:
        if (
            not certbuildutils.extensions_contains_extn_id(oid, base_extensions)
            and oid != rfc5280.id_ce_subjectKeyIdentifier
        ):
            extn = certextractutils.get_extension(csr_extensions, oid)
            base_extensions.append(extn)

    for oid in oids:
        if (
            not certbuildutils.extensions_contains_extn_id(oid, delta_extensions)
            and oid != rfc5280.id_ce_subjectKeyIdentifier
        ):
            extn = certextractutils.get_extension(delta_req_value["extensions"], oid)
            delta_extensions.append(extn)

    return base_extensions, delta_extensions


def _clean_base_and_delta_extensions(
    base_extensions: rfc9480.Extensions, delta_extensions: rfc9480.Extensions
) -> rfc9480.Extensions:
    """Remove the extension which have the same values inside the Base and Delta extensions.

    :param base_extensions: The extensions to be added to the Base Certificate.
    :param delta_extensions: The extensions to be added to the Delta Certificate.
    :return: The cleaned extensions, which only contain the differing extensions.
    """
    if not base_extensions.isValue and not delta_extensions.isValue:
        return rfc9480.Extensions()

    delta_out = rfc9480.Extensions()
    for base_ext in base_extensions:
        extn = certextractutils.get_extension(delta_extensions, base_ext["extnID"])
        if extn is None:
            pass
        elif extn["critical"] != base_ext["critical"]:
            delta_out.append(extn)
        elif extn["extnValue"].asOctets() != base_ext["extnValue"].asOctets():
            delta_out.append(extn)

    return delta_out


def _process_extension_oids(
    csr_extensions: rfc9480.Extensions,
    delta_req_value: DeltaCertificateRequestValue,
) -> Tuple[List[univ.ObjectIdentifier], List[univ.ObjectIdentifier]]:
    """Process the OIDs of the extensions in the CSR and Delta Certificate."""
    base_all_oids = [ext["extnID"] for ext in csr_extensions]
    delta_all_oids = [ext["extnID"] for ext in delta_req_value["extensions"]]
    logging.debug("Base OIDs: %s", str(base_all_oids))
    logging.debug("Delta OIDs: %s", str(delta_all_oids))

    # The extensions field contains the extensions whose criticality and/or DER-encoded
    # value are different in the Delta Certificate compared to the Base Certificate
    # with the exception of the DCD extension itself.

    # TODO should be MUST not, otherwise is it not possible to correctly
    # prepare the extensions.
    # Additionally, the Base Certificate SHALL NOT include any extensions, which
    # are not included in the Delta Certificate, with the exception of the
    # DCD extension itself.

    not_included_oids = []
    shared_oids = []
    for oid in base_all_oids:
        if oid not in delta_all_oids:
            not_included_oids.append(oid)
        else:
            shared_oids.append(oid)

    logging.debug("Not included OIDs: %s", not_included_oids)
    logging.debug("Shared OIDs: %s", shared_oids)
    return not_included_oids, shared_oids


@not_keyword
def process_extensions_for_chameleon(
    csr: rfc6402.CertificationRequest,
    delta_req_value: DeltaCertificateRequestValue,
    include_ski: Optional[bool] = None,
    additional_extensions: Optional[rfc9480.Extensions] = None,
    ski_critical: bool = False,
    strict: bool = False,
    issue_same_extensions: bool = False,
) -> Tuple[rfc9480.Extensions, rfc9480.Extensions]:
    """Prepare the extensions for the Base and Delta Certificates."""
    base_extensions = rfc9480.Extensions()
    delta_extensions = rfc9480.Extensions()

    if additional_extensions is None:
        additional_extensions = rfc9480.Extensions()

    base_extensions.extend(additional_extensions)
    delta_extensions.extend(additional_extensions)

    csr_extensions = certextractutils.extract_extensions_from_csr(csr)
    if csr_extensions is None and not delta_req_value["extensions"].isValue:
        if include_ski:
            public_key = keyutils.load_public_key_from_spki(csr["certificationRequestInfo"]["subjectPublicKeyInfo"])
            csr_ski = certbuildutils.prepare_ski_extension(key=public_key, critical=ski_critical)
            base_extensions.append(csr_ski)

            public_key = keyutils.load_public_key_from_spki(delta_req_value["subjectPKInfo"])
            delta_ski = certbuildutils.prepare_ski_extension(key=public_key, critical=ski_critical)
            delta_extensions.append(delta_ski)

        return base_extensions, delta_extensions

    if csr_extensions is not None and not delta_req_value["extensions"].isValue:
        if include_ski:
            public_key = keyutils.load_public_key_from_spki(delta_req_value["subjectPKInfo"])
            delta_ski = certbuildutils.prepare_ski_extension(key=public_key, critical=ski_critical)
            delta_extensions.append(delta_ski)

        return _parse_extension(
            csr=csr,
            target_extensions=csr_extensions,
            include_ski=include_ski,
            ski_critical=ski_critical,
        ), delta_extensions

    if delta_req_value["extensions"].isValue and csr_extensions is None:
        if include_ski:
            public_key = keyutils.load_public_key_from_spki(csr["certificationRequestInfo"]["subjectPublicKeyInfo"])
            csr_ski = certbuildutils.prepare_ski_extension(key=public_key, critical=ski_critical)
            base_extensions.append(csr_ski)

        return _parse_extension(
            csr=delta_req_value,
            target_extensions=delta_extensions,
            include_ski=include_ski,
            ski_critical=ski_critical,
        ), delta_extensions

    logging.debug("Both CSR and Delta Certificate have extensions.")
    # Both are values.

    if csr_extensions is None:
        raise ValueError("CSR extensions are missing. This path should not be called.")

    not_included_oids, shared_oids = _process_extension_oids(
        csr_extensions=csr_extensions,
        delta_req_value=delta_req_value,
    )
    if not_included_oids:
        if strict:
            raise BadCertTemplate(
                f"Base Certificate contains extensions not included in the Delta Certificate: {not_included_oids}"
            )
        if issue_same_extensions:
            return _process_remove_extensions(
                csr=csr,
                delta_req_value=delta_req_value,
                oids=shared_oids,
                include_ski=include_ski,
                ski_critical=ski_critical,
                additional_extensions=additional_extensions,
            )

        # Just parse the extensions.
        return _parse_extension(
            csr=csr,
            target_extensions=base_extensions,
            include_ski=include_ski,
            ski_critical=ski_critical,
        ), _parse_extension(
            csr=delta_req_value,
            target_extensions=delta_extensions,
            include_ski=include_ski,
            ski_critical=ski_critical,
        )

    # Have the same extensions
    return _process_remove_extensions(
        csr=csr,
        delta_req_value=delta_req_value,
        oids=shared_oids,
        include_ski=include_ski,
        ski_critical=ski_critical,
        additional_extensions=additional_extensions,
    )


@not_keyword
def build_chameleon_cert_from_paired_csr(
    csr: rfc6402.CertificationRequest,
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    alt_key: Optional[SignKey] = None,
    use_rsa_pss: bool = False,
    hash_alg: str = "sha256",
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, rfc9480.CMPCertificate]:
    """Build a Paired Certificate from a paired CSR.

    :param csr: The paired CSR.
    :param ca_key: The CA key for signing the certificate.
    :param ca_cert: The CA certificate matching the CA key.
    :param alt_key: An alternative signing key for the certificate. Defaults to `None`.
    :param hash_alg: The hash algorithm used for signing. Defaults to "sha256".
    :param use_rsa_pss: Whether to use PSS-padding for signing. Defaults to `False`.
    :return: The Paired Certificate. Starts with the Base and then Delta Certificate.
    :raises BadCertTemplate: If the Delta Certificate public key matches the Base Certificate public key.
    :raises BadAsn1Data: If the DeltaCertificateDescriptor has a remainder.
    :raises ValueError: If the DCD extension is missing.
    :raises BadPOP: If the POP signature is invalid.
    :raises BadAltPOP: If the delta POP signature is invalid.
    """
    delta_req = verify_paired_csr_signature(csr=csr)

    first_key = keyutils.load_public_key_from_spki(csr["certificationRequestInfo"]["subjectPublicKeyInfo"])
    delta_key = keyutils.load_public_key_from_spki(delta_req["subjectPKInfo"])

    _validate_keys(
        first_key=first_key,
        delta_key=delta_key,
    )

    base_extensions, delta_extensions = process_extensions_for_chameleon(
        csr=csr,
        delta_req_value=delta_req,
        include_ski=kwargs.get("include_ski"),
        additional_extensions=kwargs.get("extensions"),
        ski_critical=kwargs.get("ski_critical", False),
        strict=kwargs.get("strict", False),
        issue_same_extensions=kwargs.get("issue_same_extensions", True),
    )

    logging.debug("Base Extensions before cert building: %s", base_extensions.prettyPrint())
    logging.debug("Delta Extensions before cert building: %s", delta_extensions.prettyPrint())

    validity = kwargs.get("validity") or certbuildutils.default_validity(days=kwargs.get("days", 30))

    base_cert = certbuildutils.build_cert_from_csr(
        csr=csr,
        ca_key=ca_key,
        ca_cert=ca_cert,
        alt_sign_key=alt_key,
        use_rsa_pss=use_rsa_pss,
        include_ski=False,
        validity=validity,
        extensions=base_extensions,  # type: ignore
        include_csr_extensions=False,
    )

    delta_cert = build_delta_cert(
        csr=csr,
        delta_value=delta_req,
        ca_key=ca_key,
        ca_cert=ca_cert,
        alt_sign_key=alt_key,
        use_rsa_pss=use_rsa_pss,
        hash_alg=hash_alg,
        include_ski=False,
        validity=validity,
        extensions=delta_extensions,
        include_csr_extensions=False,
        include_delta_extensions=False,
    )

    logging.debug(
        "Delta Certificate extensions after cert building: %s", delta_cert["tbsCertificate"]["extensions"].prettyPrint()
    )
    logging.debug(
        "Base Certificate extensions after cert building: %s", base_cert["tbsCertificate"]["extensions"].prettyPrint()
    )

    paired_cert = build_chameleon_base_certificate(
        delta_cert=delta_cert,
        base_tbs_cert=base_cert["tbsCertificate"],
        ca_key=ca_key,
        use_rsa_pss=use_rsa_pss,
        hash_alg=None,  # only supposed to be used for negative testing.
    )
    logging.debug(
        "Delta Certificate extensions after after cert building: %s",
        delta_cert["tbsCertificate"]["extensions"].prettyPrint(),
    )

    return paired_cert, delta_cert


def build_delta_cert_from_paired_cert(  # noqa: D417 Missing argument description in the docstring
    paired_cert: rfc9480.CMPCertificate,
) -> rfc9480.CMPCertificate:
    """Prepare a Paired Certificate from a Base Certificate with a DeltaCertificateDescriptor (DCD) extension.

    Arguments:
    ---------
        - `paired_cert`: The Paired Certificate with the DCD extension.

    Returns:
    -------
        - The re-build Delta Certificate.

    Raises:
    ------
        - `ValueError`: If the DCD extension is missing.
        - `BadAsn1Data`: If the `DeltaCertificateDescriptor` has a remainder.
        - `ValueError`: If `DCD` Extensions are not inside the Delta Certificate.

    Examples:
    --------
    | ${delta_cert}= | Build Delta Cert From Paired Cert | ${paired_cert} |

    """
    paired_cert_tmp = copy_asn1_certificate(paired_cert)

    dcd = certextractutils.get_extension(
        paired_cert_tmp["tbsCertificate"]["extensions"], id_ce_deltaCertificateDescriptor
    )

    if dcd is None:
        raise ValueError("DCD extension not found in the Base Certificate.")

    dcd, rest = decoder.decode(dcd["extnValue"], asn1Spec=DeltaCertificateDescriptor())

    if rest:
        raise BadAsn1Data("DeltaCertificateDescriptor")

    delta_cert = rfc9480.CMPCertificate()
    delta_cert["tbsCertificate"] = paired_cert_tmp["tbsCertificate"]

    # Remove the DCD extension from the Delta Certificate template
    extensions = []

    for ext in delta_cert["tbsCertificate"]["extensions"]:
        if ext["extnID"] != id_ce_deltaCertificateDescriptor:
            extensions.append(ext)

    tmp_extn = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
    if extensions:
        tmp_extn.extend(extensions)
        delta_cert["tbsCertificate"]["extensions"] = tmp_extn

    delta_cert["tbsCertificate"]["extensions"] = tmp_extn

    # Replace fields based on the DCD extension
    delta_cert["tbsCertificate"]["serialNumber"] = int(dcd["serialNumber"])

    if dcd["signature"].isValue:
        delta_cert["tbsCertificate"]["signature"]["algorithm"] = dcd["signature"]["algorithm"]
        delta_cert["tbsCertificate"]["signature"]["parameters"] = dcd["signature"]["parameters"]
        delta_cert["signatureAlgorithm"]["algorithm"] = dcd["signature"]["algorithm"]
        delta_cert["signatureAlgorithm"]["parameters"] = dcd["signature"]["parameters"]

    else:
        delta_cert["signatureAlgorithm"]["algorithm"] = paired_cert_tmp["signatureAlgorithm"]["algorithm"]
        delta_cert["signatureAlgorithm"]["parameters"] = paired_cert_tmp["signatureAlgorithm"]["parameters"]

    if dcd["issuer"].isValue:
        issuer = copy_name(filled_name=dcd["issuer"], target=rfc5280.Name())
        delta_cert["tbsCertificate"]["issuer"] = issuer

    if dcd["validity"].isValue:
        target = rfc5280.Validity().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
        delta_cert["tbsCertificate"]["validity"] = copy_validity(filled_validity=dcd["validity"], target=target)

    delta_cert["tbsCertificate"]["subjectPublicKeyInfo"] = dcd["subjectPublicKeyInfo"]

    if dcd["subject"].isValue:
        subject = copy_name(filled_name=dcd["subject"], target=rfc5280.Name())
        delta_cert["tbsCertificate"]["subject"] = subject

    if dcd["extensions"].isValue:
        for dcd_ext in dcd["extensions"]:
            found = False
            for ext in delta_cert["tbsCertificate"]["extensions"]:
                if ext["extnID"] == dcd_ext["extnID"]:
                    ext["critical"] = dcd_ext["critical"]
                    ext["extnValue"] = dcd_ext["extnValue"]
                    found = True
                    break
            if not found:
                raise ValueError(f"Extension {dcd_ext['extnID']} not found in the Delta Certificate template.")

    delta_cert["signature"] = dcd["signatureValue"]

    return delta_cert


@keyword(name="Get Chameleon Delta Public Key")
def get_chameleon_delta_public_key(  # noqa: D417 Missing argument description in the docstring
    paired_cert: rfc9480.CMPCertificate,
) -> rfc5280.SubjectPublicKeyInfo:
    """Extract the delta public key from a Paired Certificate.

    Arguments:
    ---------
        - `paired_cert`: The Paired Certificate.

    Returns:
    -------
        - The extracted public key.

    Raises:
    ------
        - `ValueError`: If the DCD extension is missing.
        - `BadAsn1Data`: If the `DeltaCertificateDescriptor` has a remainder.

    Examples:
    --------
    | ${spki}= | Get Chameleon Delta Public Key | ${paired_cert} |

    """
    dcd = certextractutils.get_extension(paired_cert["tbsCertificate"]["extensions"], id_ce_deltaCertificateDescriptor)

    if dcd is None:
        raise ValueError("DCD extension not found in the Base Certificate.")

    dcd, rest = decoder.decode(dcd["extnValue"], asn1Spec=DeltaCertificateDescriptor())

    if rest:
        raise BadAsn1Data("DeltaCertificateDescriptor")

    return dcd["subjectPublicKeyInfo"]
