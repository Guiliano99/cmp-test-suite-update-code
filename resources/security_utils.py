# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#

"""Contain security-related utility functions, like getting the bit string of a used key."""

from typing import Optional, Union

from cryptography.hazmat.primitives.asymmetric import dsa, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from pyasn1_alt_modules import rfc4055, rfc5280, rfc8018, rfc9481
from robot.api.deco import keyword, not_keyword

from pq_logic.keys.abstract_pq import PQKEMPublicKey, PQSignaturePublicKey
from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPublicKey
from pq_logic.keys.abstract_wrapper_keys import HybridPublicKey, TradKEMPublicKey
from pq_logic.keys.stateful_sig_keys import HSSPublicKey, XMSSMTPublicKey, XMSSPublicKey
from resources.asn1utils import try_decode_pyasn1
from resources.exceptions import BadAlg
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import (
    AES_GMAC_OID_2_NAME,
    HMAC_OID_2_NAME,
    KDF_OID_2_NAME,
    KEY_WRAP_OID_2_NAME,
    KMAC_OID_2_NAME,
    PROT_SYM_ALG,
    RSASSA_PSS_OID_2_NAME,
)
from resources.typingutils import PrivateKey, PublicKey

# Security strength values follow NIST SP 800-57 Part 1 Revision 5, Tables 2 and 4.
# Table 2 provides the traditional key equivalence for RSA/DSA and ECC key sizes,
# while Table 4 lists the target security strengths for the NIST PQC levels.
_NIST_LEVEL_TO_STRENGTH = {
    1: 128,
    2: 192,
    3: 192,
    4: 256,
    5: 256,
}

HASH_ALG_TO_STRENGTH = {
    "sha1": 80,
    "sha224": 112,
    "sha256": 128,
    "sha384": 192,
    "sha512": 256,
    "sha3_224": 112,
    "sha3_256": 128,
    "sha3_384": 192,
    "sha3_512": 256,
    "shake128": 128,  # Uses in CMP 32 Byte as output size. According to RFC 9481.
    "shake256": 256,  # Uses in CMP 64 Byte as output size. According to RFC 9481.
}


def _rsa_security_strength(key_size: int) -> int:
    """Return an approximate security strength (in bits) for an RSA key size.

    Mapping follows NIST SP 800-57 Part 1 Rev. 5 Table 2.
    """
    if key_size < 1024:
        return 64

    if key_size <= 1024:
        return 80

    if key_size <= 2048:
        return 112

    if key_size <= 3072:
        return 128

    if key_size <= 7680:
        return 192

    if key_size <= 15360:
        return 256

    return 256


def _ecc_security_strength(key_size: int) -> int:
    """Return the security strength (in bits) for an ECC-style curve size.

    Mapping follows NIST SP 800-57 Part 1 Rev. 5 Table 2.
    """
    # Table 2 (ECC column: f is the field size in bits):
    # - f = 160–223  -> strength 80
    # - f = 224–255  -> strength 112
    # - f = 256–383  -> strength 128
    # - f = 384–511  -> strength 192
    # - f = 512+     -> strength 256
    if key_size <= 223:
        return 80

    if key_size <= 255:
        return 112

    if key_size <= 383:
        return 128

    if key_size <= 511:
        return 192

    return 256


def _get_pq_stfl_nist_security_strength(key: PQHashStatefulSigPublicKey) -> int:
    """Return the PQ security strength (in bits) for a PQ stateful signature key.

    XMSS and XMSS^MT security strength is determined by the hash function output size.
    According to RFC 8391 Section 5. Parameter Sets.
    The security strength is halved when considering PQ security strength, because of the `Grover` algorithm.

    :param key: The PQ stateful signature public key.
    :return: The security strength in bits.
    :raises NotImplementedError: If the key type is not supported.
    """
    if isinstance(key, XMSSPublicKey):
        return key.key_bit_security
    if isinstance(key, XMSSMTPublicKey):
        return key.key_bit_security
    if isinstance(key, HSSPublicKey):
        return key.key_bit_security

    raise NotImplementedError(
        f"Security strength estimation is only implemented for XMSS and XMSSMT keys. Got: {type(key)}"
    )


def _nist_level_strength(level: Optional[int]) -> int:
    """Translate a claimed NIST level into an approximate security strength.

    Mapping follows NIST SP 800-57 Part 1 Rev. 5 Table 4.
    """
    if level is None:
        return 0

    return _NIST_LEVEL_TO_STRENGTH.get(int(level), 0)


def estimate_key_security_strength(key: Union[PrivateKey, PublicKey]) -> int:
    """Estimate the security strength of a key in bits.

    :param key: The key to estimate the security strength for.
    :return: The estimated security strength in bits.
    :raises NotImplementedError: If the key type is not supported for security strength estimation.
    """
    if isinstance(key, PrivateKey):
        key = key.public_key()

    if isinstance(key, PQHashStatefulSigPublicKey):
        return _get_pq_stfl_nist_security_strength(key)

    if isinstance(
        key,
        (
            PQKEMPublicKey,
            PQSignaturePublicKey,
        ),
    ):
        return _nist_level_strength(key.nist_level)

    if hasattr(key, "nist_level"):
        return _nist_level_strength(getattr(key, "nist_level"))

    if isinstance(key, rsa.RSAPublicKey):
        return _rsa_security_strength(key.key_size)

    if isinstance(key, dsa.DSAPublicKey):
        return _rsa_security_strength(key.key_size)

    if isinstance(key, EllipticCurvePublicKey):
        return _ecc_security_strength(key.curve.key_size)

    if isinstance(
        key,
        (
            ed25519.Ed25519PublicKey,
            x25519.X25519PublicKey,
        ),
    ):
        return 128

    if isinstance(
        key,
        (
            ed448.Ed448PublicKey,
            x448.X448PublicKey,
        ),
    ):
        return 224

    if isinstance(key, TradKEMPublicKey):
        return estimate_key_security_strength(key._public_key)

    if isinstance(key, HybridPublicKey):
        pq_strength = estimate_key_security_strength(getattr(key, "pq_key"))
        trad_strength = estimate_key_security_strength(getattr(key, "trad_key"))
        return min(pq_strength, trad_strength)

    else:
        raise NotImplementedError(f"Security strength estimation not implemented for key type: {type(key)}")


@keyword(name="Get MAC Algorithm Bit Strength")
def get_mac_alg_id_bit_strength(alg_id: rfc5280.AlgorithmIdentifier) -> int:
    """Return the bit strength of the MAC algorithm identifier.

    :param alg_id: The AlgorithmIdentifier to get the bit strength for.
    :return: The bit strength of the MAC algorithm identifier.
    """
    oid = alg_id["algorithm"]
    if oid in HMAC_OID_2_NAME:
        return MAC_ALG_TO_STRENGTH[HMAC_OID_2_NAME[oid]]

    if oid in KMAC_OID_2_NAME:
        return MAC_ALG_TO_STRENGTH[KMAC_OID_2_NAME[oid]]

    if oid in AES_GMAC_OID_2_NAME:
        return MAC_ALG_TO_STRENGTH[AES_GMAC_OID_2_NAME[oid]]

    if oid == rfc9481.id_PasswordBasedMac:
        raise NotImplementedError("PasswordBasedMac is not supported yet.")

    if oid == rfc9481.id_PBMAC1:
        if not isinstance(alg_id["parameters"], rfc8018.PBMAC1_params):
            mac_params, _ = try_decode_pyasn1(alg_id["parameters"], rfc8018.PBMAC1_params())
        else:
            mac_params = alg_id["parameters"]

        kdf_alg_id = mac_params["keyDerivationFunc"]
        mac_alg_id = mac_params["messageAuthScheme"]

        mac_sec_strength = get_mac_alg_id_bit_strength(mac_alg_id)
        kdf_sec_strength = get_kdf_alg_id_bit_strength(kdf_alg_id)
        # TODO look up, if this is correct way, to decide the strength of the MAC algorithm.
        return min(mac_sec_strength, kdf_sec_strength)

    raise BadAlg(f"Unsupported MAC algorithm: {may_return_oid_to_name(oid)}")


@keyword(name="Get Hash Algorithm Bit Strength")
def get_hash_alg_id_bit_strength(alg_id: rfc5280.AlgorithmIdentifier) -> int:
    """Return the bit strength of the hash algorithm identifier.

    :param alg_id: The AlgorithmIdentifier to get the bit strength for.
    :return: The bit strength of the hash algorithm identifier.
    """
    name = may_return_oid_to_name(alg_id["algorithm"])
    if name not in HASH_ALG_TO_STRENGTH:
        raise BadAlg(f"Unsupported hash algorithm: {name}")
    return HASH_ALG_TO_STRENGTH[name]


