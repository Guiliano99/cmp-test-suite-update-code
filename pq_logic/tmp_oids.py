# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=invalid-name
"""Defines temporary OIDs for the test suite.

Which may change in the future or are replaced be different OIDs or updated for the final
version.
"""

from keyutils_py.oids import (  # noqa: F401  # re-exported, resources.oidutils builds on them
    CHEMPAT_NAME_2_OID,
    CHEMPAT_OID_2_NAME,
    FRODOKEM_NAME_2_OID,
    FRODOKEM_OID_2_NAME,
)
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5990, rfc9480

##############################
# Test Suite OIDs
##############################

# Define the OID for the test suite oids.
id_test_suite_oid = f"{rfc9480.id_it}.9996.9999"

# Define the OID for the test suite KEM

id_kem_test_suite = f"{id_test_suite_oid}.2"

# Define the OID for the hybrid KEM test suite.
id_hybrid_kems_test_suite = f"{id_test_suite_oid}.3"

# Define the OID for the hybrid signature test suite.
id_hybrid_sig_test_suite = f"{id_test_suite_oid}.4"


# Hybrid KEM's.
id_composite_kem_test_suite = f"{id_hybrid_kems_test_suite}.1"
id_Chempat = f"{id_hybrid_kems_test_suite}.2"


# Hybrid Signature's.

id_composite_sig_test_suite = f"{id_hybrid_sig_test_suite}.1"

# used inside cert-binding-for-multiple-authentication.
id_hybrid_sig_multi_auth = univ.ObjectIdentifier(f"{id_hybrid_sig_test_suite}.2")

# used inside the cert discovery method.
id_hybrid_sig_cert_binding = univ.ObjectIdentifier(f"{id_hybrid_sig_test_suite}.3")

# OIDs used for the sun-hybrid signature method.
id_hybrid_sun = univ.ObjectIdentifier(f"{id_hybrid_sig_test_suite}.4")

nist_algorithms_oid = rfc5990.nistAlgorithm

# Ref: https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md

id_falcon_512 = univ.ObjectIdentifier("1.3.9999.3.6")
id_falcon_1024 = univ.ObjectIdentifier("1.3.9999.3.9")

id_falcon_padded_512 = univ.ObjectIdentifier("1.3.9999.3.16")
id_falcon_padded_1024 = univ.ObjectIdentifier("1.3.9999.3.19")


FALCON_NAME_2_OID = {
    "falcon-512": id_falcon_512,
    "falcon-padded-512": id_falcon_padded_512,
    "falcon-1024": id_falcon_1024,
    "falcon-padded-1024": id_falcon_padded_1024,
}

FALCON_OID_2_NAME = {y: x for x, y in FALCON_NAME_2_OID.items()}

id_ntru = f"{id_kem_test_suite}.1"
id_sntrup761 = univ.ObjectIdentifier(f"{id_ntru}.1")


id_mceliece = f"{id_kem_test_suite}.2"

MCELIECE_NAME_2_OID = {
    "mceliece-348864": univ.ObjectIdentifier(f"{id_mceliece}.1"),
    "mceliece-460896": univ.ObjectIdentifier(f"{id_mceliece}.2"),
    "mceliece-6688128": univ.ObjectIdentifier(f"{id_mceliece}.3"),
    "mceliece-6960119": univ.ObjectIdentifier(f"{id_mceliece}.4"),
    "mceliece-8192128": univ.ObjectIdentifier(f"{id_mceliece}.5"),
}

MCELIECE_OID_2_NAME = {y: x for x, y in MCELIECE_NAME_2_OID.items()}

id_it_KemCiphertextInfo = rfc9480.id_it + (9999,)

id_rsa_kem_spki = univ.ObjectIdentifier("1.2.840.113549.1.9.16.3")

######################
# Composite SIG
######################
# Composite SIG OIDs
id_compSig_base = univ.ObjectIdentifier("1.3.6.1.5.5.7.6")

id_compSig_mldsa44_rsa2048_pss = id_compSig_base + (37,)
id_compSig_mldsa44_rsa2048_pkcs15 = id_compSig_base + (38,)
id_compSig_mldsa44_ed25519 = id_compSig_base + (39,)
id_compSig_mldsa44_ecdsa_p256 = id_compSig_base + (40,)
id_compSig_mldsa65_rsa3072_pss = id_compSig_base + (41,)
id_compSig_mldsa65_rsa3072_pkcs15 = id_compSig_base + (42,)
id_compSig_mldsa65_rsa4096_pss = id_compSig_base + (43,)
id_compSig_mldsa65_rsa4096_pkcs15 = id_compSig_base + (44,)
id_compSig_mldsa65_ecdsa_p256 = id_compSig_base + (45,)
id_compSig_mldsa65_ecdsa_p384 = id_compSig_base + (46,)
id_compSig_mldsa65_ecdsa_brainpool_p256r1 = id_compSig_base + (47,)
id_compSig_mldsa65_ed25519 = id_compSig_base + (48,)
id_compSig_mldsa87_ecdsa_p384 = id_compSig_base + (49,)
id_compSig_mldsa87_ecdsa_brainpool_p384r1 = id_compSig_base + (50,)
id_compSig_mldsa87_ed448 = id_compSig_base + (51,)
id_compSig_mldsa87_rsa3072_pss = id_compSig_base + (52,)
id_compSig_mldsa87_rsa4096_pss = id_compSig_base + (53,)
id_compSig_mldsa87_ecdsa_p521 = id_compSig_base + (54,)

COMPOSITE_SIG_NAME_TO_OID = {
    "composite-sig-ml-dsa-44-rsa2048-pss": id_compSig_mldsa44_rsa2048_pss,
    "composite-sig-ml-dsa-44-rsa2048": id_compSig_mldsa44_rsa2048_pkcs15,
    "composite-sig-ml-dsa-44-ed25519": id_compSig_mldsa44_ed25519,
    "composite-sig-ml-dsa-44-ecdsa-secp256r1": id_compSig_mldsa44_ecdsa_p256,
    "composite-sig-ml-dsa-65-rsa3072-pss": id_compSig_mldsa65_rsa3072_pss,
    "composite-sig-ml-dsa-65-rsa3072": id_compSig_mldsa65_rsa3072_pkcs15,
    "composite-sig-ml-dsa-65-rsa4096-pss": id_compSig_mldsa65_rsa4096_pss,
    "composite-sig-ml-dsa-65-rsa4096": id_compSig_mldsa65_rsa4096_pkcs15,
    "composite-sig-ml-dsa-65-ecdsa-secp256r1": id_compSig_mldsa65_ecdsa_p256,
    "composite-sig-ml-dsa-65-ecdsa-secp384r1": id_compSig_mldsa65_ecdsa_p384,
    "composite-sig-ml-dsa-65-ecdsa-brainpoolP256r1":  # line too long.
    id_compSig_mldsa65_ecdsa_brainpool_p256r1,
    "composite-sig-ml-dsa-65-ed25519": id_compSig_mldsa65_ed25519,
    "composite-sig-ml-dsa-87-ecdsa-secp384r1": id_compSig_mldsa87_ecdsa_p384,
    "composite-sig-ml-dsa-87-ecdsa-brainpoolP384r1":  # line too long.
    id_compSig_mldsa87_ecdsa_brainpool_p384r1,
    "composite-sig-ml-dsa-87-ed448": id_compSig_mldsa87_ed448,
    "composite-sig-ml-dsa-87-rsa3072-pss": id_compSig_mldsa87_rsa3072_pss,
    "composite-sig-ml-dsa-87-rsa4096-pss": id_compSig_mldsa87_rsa4096_pss,
    "composite-sig-ml-dsa-87-ecdsa-secp521r1": id_compSig_mldsa87_ecdsa_p521,
}
COMPOSITE_SIG_OID_TO_NAME = {v: k for k, v in COMPOSITE_SIG_NAME_TO_OID.items()}

COMPOSITE_SIG_LABELS = {
    id_compSig_mldsa44_rsa2048_pss: b"COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
    id_compSig_mldsa44_rsa2048_pkcs15: b"COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
    id_compSig_mldsa44_ed25519: b"COMPSIG-MLDSA44-Ed25519-SHA512",
    id_compSig_mldsa44_ecdsa_p256: b"COMPSIG-MLDSA44-ECDSA-P256-SHA256",
    id_compSig_mldsa65_rsa3072_pss: b"COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
    id_compSig_mldsa65_rsa3072_pkcs15: b"COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
    id_compSig_mldsa65_rsa4096_pss: b"COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
    id_compSig_mldsa65_rsa4096_pkcs15: b"COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
    id_compSig_mldsa65_ecdsa_p256: b"COMPSIG-MLDSA65-ECDSA-P256-SHA512",
    id_compSig_mldsa65_ecdsa_p384: b"COMPSIG-MLDSA65-ECDSA-P384-SHA512",
    id_compSig_mldsa65_ecdsa_brainpool_p256r1: b"COMPSIG-MLDSA65-ECDSA-BP256-SHA512",
    id_compSig_mldsa65_ed25519: b"COMPSIG-MLDSA65-Ed25519-SHA512",
    id_compSig_mldsa87_ecdsa_p384: b"COMPSIG-MLDSA87-ECDSA-P384-SHA512",
    id_compSig_mldsa87_ecdsa_brainpool_p384r1: b"COMPSIG-MLDSA87-ECDSA-BP384-SHA512",
    id_compSig_mldsa87_ed448: b"COMPSIG-MLDSA87-Ed448-SHAKE256",
    id_compSig_mldsa87_rsa3072_pss: b"COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
    id_compSig_mldsa87_rsa4096_pss: b"COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
    id_compSig_mldsa87_ecdsa_p521: b"COMPSIG-MLDSA87-ECDSA-P521-SHA512",
}

COMPOSITE_SIG_INNER_HASH_OID_2_NAME = {
    id_compSig_mldsa44_rsa2048_pss: "sha256",
    id_compSig_mldsa44_rsa2048_pkcs15: "sha256",
    id_compSig_mldsa44_ed25519: None,
    id_compSig_mldsa44_ecdsa_p256: "sha256",
    id_compSig_mldsa65_rsa3072_pss: "sha256",
    id_compSig_mldsa65_rsa3072_pkcs15: "sha256",
    id_compSig_mldsa65_rsa4096_pss: "sha384",
    id_compSig_mldsa65_rsa4096_pkcs15: "sha384",
    id_compSig_mldsa65_ecdsa_p256: "sha256",
    id_compSig_mldsa65_ecdsa_p384: "sha384",
    id_compSig_mldsa65_ecdsa_brainpool_p256r1: "sha256",
    id_compSig_mldsa65_ed25519: None,
    id_compSig_mldsa87_ecdsa_p384: "sha384",
    id_compSig_mldsa87_ecdsa_brainpool_p384r1: "sha384",
    id_compSig_mldsa87_ed448: None,
    id_compSig_mldsa87_rsa3072_pss: "sha256",
    id_compSig_mldsa87_rsa4096_pss: "sha384",
    id_compSig_mldsa87_ecdsa_p521: "sha512",
}

COMPOSITE_SIG_PREHASH_OID_2_HASH = {
    id_compSig_mldsa44_rsa2048_pss: "sha256",
    id_compSig_mldsa44_rsa2048_pkcs15: "sha256",
    id_compSig_mldsa44_ed25519: "sha512",
    id_compSig_mldsa44_ecdsa_p256: "sha256",
    id_compSig_mldsa65_rsa3072_pss: "sha512",
    id_compSig_mldsa65_rsa3072_pkcs15: "sha512",
    id_compSig_mldsa65_rsa4096_pss: "sha512",
    id_compSig_mldsa65_rsa4096_pkcs15: "sha512",
    id_compSig_mldsa65_ecdsa_p256: "sha512",
    id_compSig_mldsa65_ecdsa_p384: "sha512",
    id_compSig_mldsa65_ecdsa_brainpool_p256r1: "sha512",
    id_compSig_mldsa65_ed25519: "sha512",
    id_compSig_mldsa87_ecdsa_p384: "sha512",
    id_compSig_mldsa87_ecdsa_brainpool_p384r1: "sha512",
    id_compSig_mldsa87_ed448: "shake256",
    id_compSig_mldsa87_rsa3072_pss: "sha512",
    id_compSig_mldsa87_rsa4096_pss: "sha512",
    id_compSig_mldsa87_ecdsa_p521: "sha512",
}

######################
# Composite KEM
######################

# Composite KEM OIDs (draft-ietf-lamps-pq-composite-kem-14, arc: 1.3.6.1.5.5.7.6.55-66)
_COMPOSITE_KEM_MLKEM_NAMES = [
    "composite-kem-ml-kem-768-rsa2048",
    "composite-kem-ml-kem-768-rsa3072",
    "composite-kem-ml-kem-768-rsa4096",
    "composite-kem-ml-kem-768-x25519",
    "composite-kem-ml-kem-768-ecdh-secp256r1",
    "composite-kem-ml-kem-768-ecdh-secp384r1",
    "composite-kem-ml-kem-768-ecdh-brainpoolP256r1",
    "composite-kem-ml-kem-1024-rsa3072",
    "composite-kem-ml-kem-1024-ecdh-secp384r1",
    "composite-kem-ml-kem-1024-ecdh-brainpoolP384r1",
    "composite-kem-ml-kem-1024-x448",
    "composite-kem-ml-kem-1024-ecdh-secp521r1",
]

COMPOSITE_KEM_MLKEM_NAME_2_OID = {
    name: id_compSig_base + (i,) for i, name in enumerate(_COMPOSITE_KEM_MLKEM_NAMES, start=55)
}

id_ce_deltaCertificateDescriptor = univ.ObjectIdentifier("2.16.840.1.114027.80.6.1")
id_at_deltaCertificateRequestSignature = univ.ObjectIdentifier("2.16.840.1.114027.80.6.3")
id_at_deltaCertificateRequest = univ.ObjectIdentifier("2.16.840.1.114027.80.6.2")


########################
# Hybrid Signature OIDs
########################


id_relatedCert = univ.ObjectIdentifier(f"{id_hybrid_sig_multi_auth}.{1}")
id_aa_relatedCertRequest = univ.ObjectIdentifier(f"{id_hybrid_sig_multi_auth}.{2}")
id_mod_related_cert = univ.ObjectIdentifier(f"{id_hybrid_sig_multi_auth}.{3}")


id_ad_certDiscovery = univ.ObjectIdentifier(f"{id_hybrid_sig_cert_binding}.{1}")
id_ad_relatedCertificateDescriptor = univ.ObjectIdentifier(f"{id_hybrid_sig_cert_binding}.{2}")


# Hybrid SUN Signature OIDs
# CSR OIDs

id_altSubPubKeyHashAlgAttr = univ.ObjectIdentifier(f"{id_hybrid_sun}.2")
id_altSubPubKeyLocAttr = univ.ObjectIdentifier(f"{id_hybrid_sun}.3")
id_altSigValueHashAlgAttr = univ.ObjectIdentifier(f"{id_hybrid_sun}.4")
id_altSigValueLocAttr = univ.ObjectIdentifier(f"{id_hybrid_sun}.5")

# x509 OIDs

id_altSubPubKeyExt = univ.ObjectIdentifier(f"{id_hybrid_sun}.6")
id_altSignatureExt = univ.ObjectIdentifier(f"{id_hybrid_sun}.7")

# Composite KEM OIDs
COMPOSITE_KEM_NAME_2_OID = {}
COMPOSITE_KEM_NAME_2_OID.update(COMPOSITE_KEM_MLKEM_NAME_2_OID)

COMPOSITE_KEM_OID_2_NAME = {oid: name for name, oid in COMPOSITE_KEM_NAME_2_OID.items()}
