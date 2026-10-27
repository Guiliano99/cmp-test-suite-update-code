# Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: 2024 SPDX-FileCopyrightText:
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for generating, saving, and loading cryptographic keys.

Designed to facilitate key management by offering simple methods to create new keys,
store them and retrieve them when needed.
"""

import os
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from keyutils_py.enums import KeySaveType
from keyutils_py.factories import CombinedKeyFactory
from keyutils_py.keys import serialize_utils
from keyutils_py.keys.stateful_sig_keys import compute_hss_signature_index

# These are the Robot Framework keywords for the keys. They are implemented in `keyutils_py`, and are imported here so
# that this library keeps providing them (Robot Framework also exposes imported functions as keywords).
from keyutils_py.keyutils import (  # noqa: F401
    check_consistency_sig_alg_id_and_key,
    generate_key,
    generate_key_based_on_alg_id,
    get_key_name,
    load_private_key_from_file,
    load_public_key_from_file,
    load_public_key_from_spki,
    modify_pq_stateful_sig_private_key,
    prepare_subject_public_key_info,
    save_key,
)
from keyutils_py.types import (
    HSSPublicKey,
    MLDSAPrivateKey,
    MLKEMPrivateKey,
    PQHashStatefulSigPrivateKey,
    PQHashStatefulSigPublicKey,
    PrivateKey,
    PublicKey,
    RSAEncapKey,
    SLHDSAPrivateKey,
    XMSSMTPublicKey,
    XMSSPublicKey,
    XWingPrivateKey,
)
from pyasn1.codec.der import decoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc5958, rfc6402, rfc9480
from robot.api.deco import keyword, not_keyword

from resources import certutils
from resources.exceptions import BadAlg, BadCertTemplate, BadSigAlgID
from resources.oid_mapping import (
    get_digest_hash_alg_from_alg_id,
    may_return_oid_to_name,
)
from resources.oidutils import (
    PQ_STATEFUL_HASH_SIG_OID_2_NAME,
)


@keyword(name="Get PublicKey From CertTemplate")
def load_public_key_from_cert_template(  # noqa: D417 undocumented param
    cert_template: rfc4211.CertTemplate, must_be_present: bool = True
) -> Optional[PublicKey]:
    """Extract and load the public key inside a `CertTemplate`structure.

    Arguments:
    ---------
        - `cert_template`: The `CertTemplate`structure to extract the key from.
        - `must_be_present`: Whether the public key must be present. Defaults to `True`.

    Returns:
    -------
        - The loaded public key.

    Raises:
    ------
       - `BadCertTemplate`: If the `CertTemplate`structure is invalid.

    Examples:
    --------
    | ${pub_key}= | Get PublicKey From CertTemplate | ${cert_template} |
    | ${pub_key}= | Get PublicKey From CertTemplate | ${cert_template} | False

    """
    if not cert_template["publicKey"].isValue and must_be_present:
        raise BadCertTemplate("The expected public key was not inside the certificate template.")
    if not cert_template["publicKey"].isValue:
        return None

    if cert_template["publicKey"]["subjectPublicKey"].asOctets() == b"" and must_be_present:
        raise BadCertTemplate(
            "The public key was for a KGA request. The public key can not be loaded from the `CertTemplate`."
        )

    if cert_template["publicKey"]["subjectPublicKey"].asOctets() == b"":
        return None

    spki = cert_template["publicKey"]
    old_spki = rfc5280.SubjectPublicKeyInfo()
    old_spki["algorithm"] = spki["algorithm"]
    old_spki["subjectPublicKey"] = spki["subjectPublicKey"]
    try:
        return load_public_key_from_spki(old_spki)
    except (BadAlg, ValueError) as e:
        raise BadCertTemplate(f"Error loading public key from CertTemplate: {e}") from e


@not_keyword
def private_key_to_private_numbers(private_key: PrivateKey) -> bytes:
    """Return the seed or private value of the private key, to be used for key generation.

    :param private_key: The private key to extract the parameters from.
    :return: The `KeyGenParameters` structure with the extracted parameters.
    """
    if isinstance(private_key, (MLKEMPrivateKey, MLDSAPrivateKey, SLHDSAPrivateKey, XWingPrivateKey)):
        data = private_key.private_numbers()

    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        private_nums = private_key.private_numbers()
        data = private_nums.private_value.to_bytes((private_nums.private_value.bit_length() + 7) // 8, "big")

    elif isinstance(
        private_key,
        (
            x25519.X25519PrivateKey,
            ed25519.Ed25519PrivateKey,
            x448.X448PrivateKey,
            ed448.Ed448PrivateKey,
        ),
    ):
        data = private_key.private_bytes_raw()

    elif isinstance(private_key, rsa.RSAPrivateKey):
        data = serialize_utils.prepare_rsa_private_key(private_key)

    else:
        raise ValueError(f"Unsupported private key type: {private_key}. Cannot extract key generation parameters.")

    return data


def generate_different_public_key(  # noqa D417 undocumented-param
    key_source: Union[rfc9480.CMPCertificate, rfc6402.CertificationRequest, PrivateKey, PublicKey],
    algorithm: Optional[str] = None,
) -> PublicKey:
    """Generate a new public key using the specified algorithm, ensuring it differs from the certificate's public key.

    Used to ensure the revocation request sends a different public key but for the same type.

    Arguments:
    ---------
        - `key_source`: The certificate from which to extract the existing public key or a key object.
        - `algorithm`: The algorithm to use for generating the new key pair (e.g., `"rsa"`, `"ec"`).

    Raises:
    ------
        - `ValueError`: If the function fails to generate a different public key after 100 attempts.

    Returns:
    -------
        - The generated public key, guaranteed to be different from the public key in `cert`.

    Examples:
    --------
    | ${new_public_key}= | Generate Different Public Key | cert=${certificate} | algorithm="rsa" |
    | ${new_public_key}= | Generate Different Public Key | cert=${certificate} | algorithm="ec" |

    """
    if isinstance(key_source, rfc9480.CMPCertificate):
        spki = key_source["tbsCertificate"]["subjectPublicKeyInfo"]
        public_key = load_public_key_from_spki(spki)

    elif isinstance(key_source, rfc6402.CertificationRequest):
        spki = key_source["certificationRequestInfo"]["subjectPublicKeyInfo"]
        public_key = load_public_key_from_spki(spki)

    elif isinstance(key_source, PrivateKey):
        public_key = key_source.public_key()
    else:
        public_key = key_source

    length = None
    curve_name = None
    if isinstance(public_key, RSAEncapKey):
        length = public_key._public_key.key_size  # type: ignore
    elif isinstance(public_key, RSAPublicKey):
        length = public_key.key_size
    elif isinstance(public_key, EllipticCurvePublicKey):
        curve_name = public_key.curve.name

    # just to reduce the extremely slim chance, they are actually the same.
    pub_key = None
    key_name = get_key_name(public_key)
    for _ in range(100):
        if algorithm is not None:
            pub_key = generate_key(algorithm=algorithm, length=length, curve=curve_name).public_key()
        else:
            pub_key = generate_key(algorithm=key_name, by_name=True).public_key()
        if pub_key != public_key:
            break
        pub_key = None

    if pub_key is None:
        raise ValueError("Failed to generate a different public key.")

    return pub_key


def _get_version_and_tmp_version(version: Union[int, str]) -> Tuple[int, int]:
    """Get the version and temporary version for the `OneAsymmetricKey` structure.

    :param version: The version of the structure. Can be an integer or a string.
    :return: A tuple containing the version and temporary version.
    :raises ValueError: If the string version is not valid.
    """
    if isinstance(version, int):
        tmp_version = 1 if version >= 1 else 0
    elif isinstance(version, str) and not version.isdigit():
        if version not in ["v1", "v2"]:
            raise ValueError("Invalid version only supports 'v1', 'v2'")
        version = 1 if version == "v2" else 0
        tmp_version = version
    else:
        version = int(version)
        tmp_version = 1 if version >= 1 else 0

    return version, tmp_version


def _prepare_one_asym_key(
    private_key_bytes: bytes,
    public_key_bytes: Optional[bytes],
    version: int,
    alg_id: rfc5280.AlgorithmIdentifier,
) -> rfc5958.OneAsymmetricKey:
    """Parse the `OneAsymmetricKey` structure from the given bytes.

    :param private_key_bytes: The private key bytes.
    :param public_key_bytes: The public key bytes, if available.
    :param version: The version of the structure.
    :param alg_id: The algorithm identifier.
    :return: The parsed `OneAsymmetricKey` structure.
    """
    one_asym_key = rfc5958.OneAsymmetricKey()
    one_asym_key["version"] = univ.Integer(version)
    one_asym_key["privateKeyAlgorithm"] = alg_id
    one_asym_key["privateKey"] = univ.OctetString(private_key_bytes)
    if public_key_bytes is not None:
        public_key_bit_str = (
            rfc5958.PublicKey()
            .fromOctetString(public_key_bytes)
            .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
        )
        one_asym_key["publicKey"] = public_key_bit_str
    return one_asym_key


@keyword(name="Prepare OneAsymmetricKey")
def prepare_one_asymmetric_key(  # noqa: D417 undocumented-params
    private_key: PrivateKey,
    public_key: Optional[PublicKey] = None,
    version: Union[int, str] = "v2",
    key_save_type: Union[str, KeySaveType] = "seed",
    invalid_priv_key_size: bool = False,
    invalid_pub_key_size: bool = False,
    mis_matching_key: bool = False,
    invalid_private_key: bool = False,
    include_public_key: Optional[bool] = None,
) -> rfc5958.OneAsymmetricKey:
    """Create a `OneAsymmetricKey` structure for a private key.

    Wraps a private key into the `OneAsymmetricKey` structure,
    including the algorithm identifier and the public key. It's used when
    preparing an `AsymmetricKeyPackage`.

    Arguments:
    ---------
        - `private_key`: The private key to wrap.
        - `version`: The version of the structure. Defaults to "v2".
        - `key_save_type`: The type of key to save. Can be "seed", "raw", or "seed_and_raw". Defaults to "raw".
        - `invalid_private_key`: If True, the private key is invalid. Only supported for RSA, ECC,
        ML-DSA and ML-KEM keys. Defaults to `False`.
        - `invalid_pub_key_size`: If True, the public key size is invalid. Defaults to `False`.
        - `mis_matching_key`: If True, the public key does not match the private key. Defaults to `False`.
        - `invalid_priv_key_size`: If True, the private key size is invalid. Defaults to `False`.
        - `include_public_key`: If True, the public key is included in the structure. If `None`, \
        it is set to `False` for version 0. Defaults to `None`.

    Returns:
    -------
        - The populated `OneAsymmetricKey` structure.

    Raises:
    ------
        - `ValueError`: If the private key is not of a supported type or if the version is invalid.
        - `ValueError`: If the key_save_type is invalid.
        - `ValueError`: If the string version is not supported.
        - `ValueError`: If the private key is invalid and the invalid_priv_key option is set.

    Examples:
    --------
    | ${one_asym_key}= | Prepare OneAsymmetricKey | ${private_key} | "v2" |
    | ${one_asym_key}= | Prepare OneAsymmetricKey | ${private_key} | key_save_type="seed" |

    """
    if (
        not isinstance(private_key, (RSAPrivateKey, EllipticCurvePrivateKey, MLDSAPrivateKey, MLKEMPrivateKey))
        and invalid_private_key
    ):
        raise ValueError(
            "The invalid private key option is only supported for `RSA`, `ECC`, `ML-DSA` and `ML-KEM` keys."
        )

    if mis_matching_key:
        public_key = generate_different_public_key(key_source=private_key)

    version, tmp_version = _get_version_and_tmp_version(version)

    if include_public_key is None:
        if version in ["v1", 0]:
            include_public_key = False

    der_data = CombinedKeyFactory.save_private_key_one_asym_key(
        private_key=private_key,
        public_key=public_key,
        save_type=key_save_type,
        version=tmp_version,
        include_public_key=include_public_key,
        invalid_private_key=invalid_private_key,
        password=None,
        unsafe=True,
    )
    one_asym_key, _ = decoder.decode(der_data, asn1Spec=rfc5958.OneAsymmetricKey())

    public_key_bytes = None if not one_asym_key["publicKey"].isValue else one_asym_key["publicKey"].asOctets()
    private_key_bytes = one_asym_key["privateKey"].asOctets()

    if invalid_priv_key_size:
        private_key_bytes = private_key_bytes + os.urandom(16)

    if invalid_pub_key_size:
        public_key_bytes = b"" if public_key_bytes is None else public_key_bytes
        public_key_bytes = public_key_bytes + os.urandom(16)

    return _prepare_one_asym_key(
        private_key_bytes=private_key_bytes,
        public_key_bytes=public_key_bytes,
        version=version,
        alg_id=one_asym_key["privateKeyAlgorithm"],
    )


@keyword(name="Get Digest Alg For CMP")
def get_digest_alg_for_cmp(  # noqa D417 undocumented-param
    alg_id: rfc9480.AlgorithmIdentifier, cert_or_pub_key: Optional[Union[rfc9480.CMPCertificate, PublicKey]] = None
) -> str:
    """Get the hash algorithm for the SignedData or the certificate confirmation computation.

    Note:
    ----
    - For stateful hash signatures (e.g., XMSS, HSS), the public key or certificate must be provided
      to determine the hash algorithm.
    - For other signature algorithms, the hash algorithm is extracted directly from the AlgorithmIdentifier.

    Arguments:
    ---------
    - `alg_id`: The AlgorithmIdentifier for the signing.
    - `cert_or_pub_key`: Optional certificate or public key to determine the hash algorithm if needed.

    Raises:
    ------
    - `ValueError`: If the public key or certificate is required but not provided for stateful hash signatures.
    - `BadSigAlgID`: If the provided public key is not a stateful hash signature public key when required.

    Examples:
    --------
    | ${hash_alg}= | Get Digest Alg For CMP | ${alg_id} | ${certificate} |
    | ${hash_alg}= | Get Digest Alg For CMP | ${alg_id} | ${public_key} |

    """
    oid = alg_id["algorithm"]
    if oid in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
        if cert_or_pub_key is None:
            raise ValueError("For stateful hash signatures, the public key or certificate must be provided.")
        if isinstance(cert_or_pub_key, rfc9480.CMPCertificate):
            pub_key = certutils.load_public_key_from_cert(cert_or_pub_key)
        else:
            pub_key = cert_or_pub_key

        if not isinstance(pub_key, PQHashStatefulSigPublicKey):
            msg = (
                "Provided public key is not a stateful hash signature public key, despite the OID."
                f"Public key type: {type(pub_key).__name__}: {may_return_oid_to_name(oid)}"
            )

            raise BadSigAlgID(msg)

        return pub_key.hash_alg

    return get_digest_hash_alg_from_alg_id(alg_id)


@keyword(name="Get PQ Stateful Sig Index From Sig")
def get_pq_stateful_sig_index_from_sig(  # noqa D417 undocumented-params
    signature: bytes,
    key: Union[PQHashStatefulSigPrivateKey, PQHashStatefulSigPublicKey],
    return_lms_index: bool = False,
) -> int:
    """Extract the signature index from a PQ stateful signature.

    Note:
    ----
    - For HSS signatures, the index is computed which matches the actual used index for
    the private key (not the LMS leaf index).

    Arguments:
    ---------
    - `signature`: The signature bytes from which to extract the index.
    - `key`: The PQ stateful signature key (private or public) associated with the signature.
    - `return_lms_index`: If `True` and the key is an HSS key, return the LMS leaf index instead \
    of the HSS signature index.

    Returns:
    -------
    - The extracted signature index as an integer.

    Raises:
    ------
    - `NotImplementedError`: If the key type is unsupported for signature index extraction.

    Examples:
    --------
    | ${sig_index}= | Get PQ Stateful Sig Index From Sig | ${signature} | ${pq_stateful_sig_key} |
    | ${sig_index}= | Get PQ Stateful Sig Index From Sig | ${signature} | ${pq_stateful_sig_key} | True |

    """
    if isinstance(key, PQHashStatefulSigPrivateKey):
        key = key.public_key()

    if isinstance(key, HSSPublicKey):
        if return_lms_index:
            return key.get_leaf_index(signature=signature)
        return compute_hss_signature_index(signature, key)

    if isinstance(key, (XMSSPublicKey, XMSSMTPublicKey)):
        return key.get_leaf_index(signature)

    raise NotImplementedError(f"Unsupported key type for signature index extraction. Got: {type(key).__name__}")
