# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import unittest
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key
from pyasn1_alt_modules import rfc9480

from pq_logic.keys.composite_sig07 import CompositeSig07PrivateKey, CompositeSig07PublicKey
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pq_logic.keys.sig_keys import MLDSAPrivateKey
from resources.certutils import parse_certificate
from resources.oidutils import CURVE_NAMES_TO_INSTANCES

COMPOSITE_SIG07_NAME_TO_ORIGINAL_NAME = {
    "composite-sig-07-ml-dsa-44-rsa2048-pss": "id-MLDSA44-RSA2048-PSS-SHA256",
    "composite-sig-07-ml-dsa-44-rsa2048": "id-MLDSA44-RSA2048-PKCS15-SHA256",
    "composite-sig-07-ml-dsa-44-ed25519": "id-MLDSA44-Ed25519-SHA512",
    "composite-sig-07-ml-dsa-44-ecdsa-secp256r1": "id-MLDSA44-ECDSA-P256-SHA256",
    "composite-sig-07-ml-dsa-65-rsa3072-pss": "id-MLDSA65-RSA3072-PSS-SHA512",
    "composite-sig-07-ml-dsa-65-rsa3072": "id-MLDSA65-RSA3072-PKCS15-SHA512",
    "composite-sig-07-ml-dsa-65-rsa4096-pss": "id-MLDSA65-RSA4096-PSS-SHA512",
    "composite-sig-07-ml-dsa-65-rsa4096": "id-MLDSA65-RSA4096-PKCS15-SHA512",
    "composite-sig-07-ml-dsa-65-ecdsa-secp256r1": "id-MLDSA65-ECDSA-P256-SHA512",
    "composite-sig-07-ml-dsa-65-ecdsa-secp384r1": "id-MLDSA65-ECDSA-P384-SHA512",
    "composite-sig-07-ml-dsa-65-ecdsa-brainpoolP256r1": "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512",
    "composite-sig-07-ml-dsa-65-ed25519": "id-MLDSA65-Ed25519-SHA512",
    "composite-sig-07-ml-dsa-87-ecdsa-secp384r1": "id-MLDSA87-ECDSA-P384-SHA512",
    "composite-sig-07-ml-dsa-87-ecdsa-brainpoolP384r1": "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512",
    "composite-sig-07-ml-dsa-87-ed448": "id-MLDSA87-Ed448-SHAKE256",
    "composite-sig-07-ml-dsa-87-rsa3072-pss": "id-MLDSA87-RSA3072-PSS-SHA512",
    "composite-sig-07-ml-dsa-87-rsa4096-pss": "id-MLDSA87-RSA4096-PSS-SHA512",
    "composite-sig-07-ml-dsa-87-ecdsa-secp521r1": "id-MLDSA87-ECDSA-P521-SHA512",
}

COMPOSITE_SIG07_ORIGINAL_NAME_TO_NAME = {v: k for k, v in COMPOSITE_SIG07_NAME_TO_ORIGINAL_NAME.items()}


def _load_composite_sig07_from_private_bytes(algorithm: str, private_key: bytes) -> CompositeSig07PrivateKey:
    """Load a composite signature key from private bytes.

    :param algorithm: The name of the algorithm, e.g., "composite-sig-07-ml-dsa-44-rsa2048-pss".
    :param private_key: The private key bytes, which should be 64 bytes for ML-DSA keys and 32 bytes for traditional keys.
    :return: A CompositeSig06PrivateKey instance.
    """
    algorithm = algorithm.lower()
    prefix = "composite-sig-07-"
    pq_name = PQKeyFactory.get_pq_alg_name(algorithm=algorithm)
    pq_key, trad_bytes = private_key[:32], private_key[32:]
    pq_key = MLDSAPrivateKey.from_private_bytes(pq_key, name=pq_name)

    trad_name = algorithm.replace(prefix, "").replace(pq_name + "-", "")
    if trad_name == "ed448":
        trad_key = Ed448PrivateKey.from_private_bytes(private_key[32:])
    elif trad_name == "ed25519":
        trad_key = Ed25519PrivateKey.from_private_bytes(private_key[32:])
    else:
        trad_key = load_der_private_key(trad_bytes, password=None)

    return CompositeSig07PrivateKey(
        pq_key=pq_key,
        trad_key=trad_key,
    )


def _load_composite_sig06_from_public_bytes(algorithm: str, public_key: bytes) -> CompositeSig07PublicKey:
    """Load a composite signature public key from public bytes.

    :param algorithm: The name of the algorithm, e.g., "composite-sig-07-ml-dsa-44-rsa2048-pss".
    :param public_key: The public key bytes.
    :return: A CompositeSig06PublicKey instance.
    """
    algorithm = algorithm.lower()
    prefix = "composite-sig-07-"
    pq_name = PQKeyFactory.get_pq_alg_name(algorithm=algorithm)
    trad_name = algorithm.replace(prefix, "").replace(pq_name + "-", "")
    pq_key, rest = PQKeyFactory.from_public_bytes(pq_name, public_key, allow_rest=True)

    if trad_name == "ed448":
        trad_key = Ed448PublicKey.from_public_bytes(rest)
    elif trad_name == "ed25519":
        trad_key = Ed25519PublicKey.from_public_bytes(rest)
    elif trad_name.startswith("ecdsa-"):
        curve_name = trad_name.replace("ecdsa-", "")
        curve = CURVE_NAMES_TO_INSTANCES.get(curve_name)
        if curve is None:
            raise ValueError(f"Unsupported ECDSA curve: {curve_name}")
        trad_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, rest)

    else:
        trad_key = load_der_public_key(rest)

    return CompositeSig07PublicKey(
        pq_key=pq_key,
        trad_key=trad_key,
    )


@dataclass
class TestVectorEntry:
    tcId: str  # The name of the algorithm.
    pk: str  #  The public key in hex format.
    x5c: str  # The X.509 self-signed certificate in hex format.
    sk: str  # RAW signature secret key in hex format.
    sk_pkcs8: str  # PKCS#8 encoded secret key in hex format.
    s: str  # The signature in hex format.

    _sk_key: Optional[CompositeSig07PrivateKey] = None

    @classmethod
    def from_dict(cls, data: dict):
        """Create a TestVectorEntry from a dictionary."""
        return cls(
            tcId=data["tcId"], pk=data["pk"], x5c=data["x5c"], sk=data["sk"], sk_pkcs8=data["sk_pkcs8"], s=data["s"]
        )

    def secret_key(self) -> CompositeSig07PrivateKey:
        """Return the secret key as a CompositeSig06PrivateKey."""
        _name = COMPOSITE_SIG07_ORIGINAL_NAME_TO_NAME[self.tcId]

        if self._sk_key is not None:
            return self._sk_key

        sk_bytes = base64.decodebytes(self.sk.encode("ascii"))

        self._sk_key = _load_composite_sig07_from_private_bytes(algorithm=_name, private_key=sk_bytes)
        return self._sk_key

    def public_key(self) -> CompositeSig07PublicKey:
        """Return the public key as bytes."""
        _name = self.name
        if self._sk_key is None:
            self.secret_key()
        return self._sk_key.public_key()

    @property
    def name(self) -> str:
        """Return the name of the test vector."""
        return COMPOSITE_SIG07_ORIGINAL_NAME_TO_NAME[self.tcId]

    @property
    def signature(self) -> bytes:
        """Return the signature as bytes."""
        return base64.decodebytes(self.s.encode("ascii"))

    @property
    def certificate(self) -> rfc9480.CMPCertificate:
        """Return the X.509 certificate as bytes."""
        der_data = base64.decodebytes(self.x5c.encode("ascii"))
        return parse_certificate(der_data)

    def validate(self):
        """Validate the test vector entry."""
        private_key = self.secret_key()  # Ensure the secret key is loaded
        spki = self.certificate["tbsCertificate"]["subjectPublicKeyInfo"]
        public_key_bytes = spki["subjectPublicKey"].asOctets()
        public_key = _load_composite_sig06_from_public_bytes(self.name, public_key_bytes)
        if public_key != private_key.public_key():
            raise ValueError("Public key does not match the private key's public key.")


class TestCompositeSig07TestVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = "./data/rfc_test_vectors/composite_sig07_testvectors.json"
        cls.test_vectors = cls.load_test_vectors(cls.path)
        cls.m = base64.decodebytes(cls.test_vectors["m"].encode("ascii"))
        cls.test_cases = cls.test_vectors["tests"]

    @staticmethod
    def load_test_vectors(path: str):
        """Load test vectors from a JSON file."""
        with open(path, "r") as file:
            return json.load(file)

    def test_composite_sig06_vectors_ed(self):
        """
        GIVEN a set of composite signature test vectors for EdDSA.
        WHEN the vectors are tested,
        THEN the signatures should be verified successfully.
        """
        for vector in self.test_cases:
            if vector["tcId"] in ["id-ML-DSA-44", "id-ML-DSA-65", "id-ML-DSA-87"]:
                # Skip these test cases as they are not composite signatures
                continue

            if "ED" not in vector["tcId"]:
                # Skip non-ED test cases
                continue

            with self.subTest(vector=vector["tcId"]):
                # Here you would implement the logic to test each vector.
                # For example, you might call a function that processes the vector
                # and assert the expected results.

                test_vec = TestVectorEntry.from_dict(vector)  # Convert to TestVectorEntry for type safety
                print(f"Testing vector: {test_vec.name}")
                cert = test_vec.certificate
                public_key = test_vec.public_key()
                self.assertIsInstance(
                    public_key, CompositeSig07PublicKey, "Public key should be of type CompositeSig06PublicKey"
                )
                use_pss = False
                if "pss" in test_vec.name:
                    use_pss = True
                test_vec.validate()
                public_key.verify(data=self.m, signature=test_vec.signature, use_pss=use_pss)

    def test_composite_sig06_vectors_ecc(self):
        """
        GIVEN a set of composite signature test vectors for ECDSA.
        WHEN the vectors are tested,
        THEN the signatures should be verified successfully.
        """
        for vector in self.test_cases:
            if vector["tcId"] in ["id-ML-DSA-44", "id-ML-DSA-65", "id-ML-DSA-87"]:
                # Skip these test cases as they are not composite signatures
                continue

            if "ECDSA" not in vector["tcId"]:
                # Skip ED test cases
                continue

            with self.subTest(vector=vector["tcId"]):
                test_vec = TestVectorEntry.from_dict(vector)
                print(f"Testing vector: {test_vec.name}")
                _ = test_vec.certificate
                public_key = test_vec.public_key()
                self.assertIsInstance(
                    public_key, CompositeSig07PublicKey, "Public key should be of type CompositeSig06PublicKey"
                )
                test_vec.validate()
                public_key.verify(data=self.m, signature=test_vec.signature)

    def test_composite_sig06_vectors_rsa(self):
        """
        GIVEN a set of composite signature test vectors for RSA.
        WHEN the vectors are tested,
        THEN the signatures should be verified successfully.
        """
        for vector in self.test_cases:
            if vector["tcId"] in ["id-ML-DSA-44", "id-ML-DSA-65", "id-ML-DSA-87"]:
                # Skip these test cases as they are not composite signatures
                continue

            if "RSA" not in vector["tcId"]:
                # Skip ED and ECC test cases
                continue

            with self.subTest(vector=vector["tcId"]):
                test_vec = TestVectorEntry.from_dict(vector)
                _ = test_vec.certificate
                public_key = test_vec.public_key()
                self.assertIsInstance(
                    public_key, CompositeSig07PublicKey, "Public key should be of type CompositeSig06PublicKey"
                )
                use_pss = False
                if "pss" in test_vec.name:
                    use_pss = True
                test_vec.validate()
                public_key.verify(data=self.m, signature=test_vec.signature, use_pss=use_pss)
