# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import base64
import unittest
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_private_key, load_der_public_key

from pq_logic.keys.composite_kem08 import CompositeKEM08PrivateKey, CompositeKEM08PublicKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pq_logic.keys.trad_kem_keys import DHKEMPrivateKey, RSADecapKey, RSAEncapKey
from resources.certutils import parse_certificate
from resources.exceptions import InvalidKeyData
from resources.oidutils import CURVE_NAMES_TO_INSTANCES

COMPOSITE_KEM08_ORIGINAL_NAME_TO_NAME = {
    "id-MLKEM768-RSA2048-SHA3-256": "composite-kem08-ml-kem-768-rsa2048",
    "id-MLKEM768-RSA3072-SHA3-256": "composite-kem08-ml-kem-768-rsa3072",
    "id-MLKEM768-RSA4096-SHA3-256": "composite-kem08-ml-kem-768-rsa4096",
    "id-MLKEM768-X25519-SHA3-256": "composite-kem08-ml-kem-768-x25519",
    "id-MLKEM768-ECDH-P256-SHA3-256": "composite-kem08-ml-kem-768-ecdh-secp256r1",
    "id-MLKEM768-ECDH-P384-SHA3-256": "composite-kem08-ml-kem-768-ecdh-secp384r1",
    "id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256": "composite-kem08-ml-kem-768-ecdh-brainpoolP256r1",
    "id-MLKEM1024-RSA3072-SHA3-256": "composite-kem08-ml-kem-1024-rsa3072",
    "id-MLKEM1024-ECDH-P384-SHA3-256": "composite-kem08-ml-kem-1024-ecdh-secp384r1",
    "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256": "composite-kem08-ml-kem-1024-ecdh-brainpoolP384r1",
    "id-MLKEM1024-X448-SHA3-256": "composite-kem08-ml-kem-1024-x448",
    "id-MLKEM1024-ECDH-P521-SHA3-256": "composite-kem08-ml-kem-1024-ecdh-secp521r1",
}


@dataclass
class CompositeKEM08TestVectors:
    """Test vectors for Composite KEM draft-08."""

    tcId: str
    ek: str
    x5c: str
    dk: str
    dk_pkcs8: str
    c: str
    k: str

    @classmethod
    def from_dict(cls, data: dict) -> "CompositeKEM08TestVectors":
        return cls(
            tcId=data["tcId"],
            ek=data["ek"],
            x5c=data["x5c"],
            dk=data["dk"],
            dk_pkcs8=data["dk_pkcs8"],
            c=data["c"],
            k=data["k"],
        )

    @property
    def ss(self):
        """Compute the shared secret from the key."""
        return base64.b64decode(self.k)

    @property
    def ek_bytes(self):
        """Get the encryption key as bytes."""
        return base64.b64decode(self.ek)

    @property
    def certificate(self):
        """Get the X.509 certificate."""
        der_data = base64.b64decode(self.x5c)
        return parse_certificate(der_data)

    @property
    def dk_bytes(self):
        """Get the decryption key as bytes."""
        return base64.b64decode(self.dk)

    @property
    def name(self):
        """Get the name of the algorithm."""
        return COMPOSITE_KEM08_ORIGINAL_NAME_TO_NAME[self.tcId]

    @property
    def ct_bytes(self):
        """Get the ciphertext as bytes."""
        return base64.b64decode(self.c)


def _deserialize_traditional_private_key(trad_name: str, trad_pk: bytes, trad_sk: bytes):
    """Deserialize the traditional key material as defined in draft-08 Section 5.2."""
    if not trad_pk or not trad_sk:
        raise InvalidKeyData("Traditional key material is incomplete.")

    if trad_name.startswith("rsa"):
        private_key = load_der_private_key(trad_sk, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise InvalidKeyData("Expected an RSA private key.")
        expected_bits = int(trad_name.replace("rsa", "", 1))
        if private_key.key_size != expected_bits:
            raise InvalidKeyData(f"Expected RSA key size {expected_bits}, but got {private_key.key_size}.")
        expected_pk = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1)
        if expected_pk != trad_pk:
            raise InvalidKeyData("RSA public key does not match the private key.")
        return RSADecapKey(private_key)

    if trad_name == "x25519":
        private_key = X25519PrivateKey.from_private_bytes(trad_sk)
        expected_pk = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if expected_pk != trad_pk:
            raise InvalidKeyData("X25519 public key does not match the private key.")
        return DHKEMPrivateKey(private_key=private_key, use_rfc9180=False)

    if trad_name == "x448":
        private_key = X448PrivateKey.from_private_bytes(trad_sk)
        expected_pk = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if expected_pk != trad_pk:
            raise InvalidKeyData("X448 public key does not match the private key.")
        return DHKEMPrivateKey(private_key=private_key, use_rfc9180=False)

    if trad_name.startswith("ecdh-"):
        curve_name = trad_name.replace("ecdh-", "", 1)
        curve = CURVE_NAMES_TO_INSTANCES.get(curve_name)
        if curve is None:
            raise ValueError(f"Unsupported ECDH curve: {curve_name}")
        private_key = load_der_private_key(trad_sk, password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise InvalidKeyData("Expected an ECDH private key.")
        if private_key.curve.name.lower() != curve_name.lower():
            raise InvalidKeyData(f"Expected ECDH curve {curve_name}, but got {private_key.curve.name}.")
        expected_pk = private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        if expected_pk != trad_pk:
            raise InvalidKeyData("ECDH public key does not match the private key.")
        return DHKEMPrivateKey(private_key=private_key, use_rfc9180=False)

    raise ValueError(f"Unsupported traditional key type: {trad_name}")


def _load_composite_kem08_from_private_bytes(algorithm: str, private_key: bytes) -> CompositeKEM08PrivateKey:
    """Load a Composite KEM draft-08 private key from raw bytes."""
    algorithm = algorithm.lower()
    if algorithm.startswith("composite-kem-08-"):
        algorithm = algorithm.replace("composite-kem-08-", "composite-kem08-", 1)

    prefix = "composite-kem08-"
    pq_name = PQKeyFactory.get_pq_alg_name(algorithm=algorithm)
    trad_name = algorithm.replace(prefix, "").replace(pq_name + "-", "", 1)

    if len(private_key) < 66:
        raise InvalidKeyData("Composite private key is too short.")

    mlkem_seed = private_key[:64]
    if len(mlkem_seed) != 64:
        raise InvalidKeyData("ML-KEM seed must be 64 bytes.")

    len_trad_pk = int.from_bytes(private_key[64:66], byteorder="little")
    offset = 66
    if len(private_key) < offset + len_trad_pk:
        raise InvalidKeyData("Composite private key is missing the traditional public key.")

    trad_pk = private_key[offset : offset + len_trad_pk]
    offset += len_trad_pk
    trad_sk = private_key[offset:]
    if not trad_sk:
        raise InvalidKeyData("Composite private key is missing the traditional private key.")

    pq_key = MLKEMPrivateKey.from_private_bytes(data=mlkem_seed, name=pq_name)
    trad_key = _deserialize_traditional_private_key(trad_name, trad_pk, trad_sk)

    return CompositeKEM08PrivateKey(
        pq_key=pq_key,
        trad_key=trad_key,
    )


def _load_composite_kem08_from_public_bytes(algorithm: str, public_key: bytes) -> CompositeKEM08PublicKey:
    """Load a Composite KEM draft-08 public key from raw bytes."""
    algorithm = algorithm.lower()
    if algorithm.startswith("composite-kem-08-"):
        algorithm = algorithm.replace("composite-kem-08-", "composite-kem08-", 1)

    prefix = "composite-kem08-"
    pq_name = PQKeyFactory.get_pq_alg_name(algorithm=algorithm)
    trad_name = algorithm.replace(prefix, "").replace(pq_name + "-", "")
    pq_key, rest = PQKeyFactory.from_public_bytes(pq_name, public_key, allow_rest=True)

    if trad_name == "x25519":
        trad_key = X25519PublicKey.from_public_bytes(rest)
    elif trad_name == "x448":
        trad_key = X448PublicKey.from_public_bytes(rest)
    elif trad_name.startswith("ecdh-"):
        curve_name = trad_name.replace("ecdh-", "")
        curve = CURVE_NAMES_TO_INSTANCES.get(curve_name)
        if curve is None:
            raise ValueError(f"Unsupported ECDH curve: {curve_name}")
        trad_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, rest)
    elif trad_name.startswith("rsa"):
        trad_key = load_der_public_key(rest)
        trad_key = RSAEncapKey(trad_key)
    else:
        raise ValueError(f"Unsupported traditional key type: {trad_name}")

    return CompositeKEM08PublicKey(
        pq_key=pq_key,
        trad_key=trad_key,
    )


class TestCompositeKEM08TestVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = "./data/rfc_test_vectors/composite_kem08_testvectors.json"
        cls.test_vectors = cls.load_test_vectors(cls.path)

    @staticmethod
    def load_test_vectors(path: str) -> list[CompositeKEM08TestVectors]:
        import json

        with open(path, "r") as file:
            data = json.load(file)

        tests_vectors = []
        for test in data["tests"]:
            if test["tcId"] in ["id-alg-ml-kem-768", "id-alg-ml-kem-1024"]:
                continue
            tests_vectors.append(CompositeKEM08TestVectors.from_dict(test))

        return tests_vectors

    def test_decaps_composite_rsa_key(self):
        """
        GIVEN a Composite KEM draft-08 test vector with RSA keys,
        WHEN the key is loaded from bytes,
        THEN it should match the expected values.
        """
        for vector in self.test_vectors:
            if "RSA" not in vector.tcId:
                continue

            with self.subTest(tcId=vector.tcId):
                private_key = _load_composite_kem08_from_private_bytes(
                    algorithm=vector.name, private_key=vector.dk_bytes
                )
                self.assertIsInstance(private_key, CompositeKEM08PrivateKey)
                self.assertIsInstance(private_key.pq_key, MLKEMPrivateKey)
                self.assertIsInstance(private_key.trad_key, RSADecapKey)
                self.assertEqual(private_key.pq_key.name, PQKeyFactory.get_pq_alg_name(vector.name))
                ss_out = private_key.decaps(vector.ct_bytes)
                self.assertEqual(ss_out.hex(), vector.ss.hex())

    def test_decaps_composite_ecdh_key(self):
        """
        GIVEN a Composite KEM draft-08 test vector with ECDH keys,
        WHEN the key is loaded from bytes,
        THEN it should match the expected values.
        """
        for vector in self.test_vectors:
            if "ECDH" not in vector.tcId:
                continue

            with self.subTest(tcId=vector.tcId):
                private_key = _load_composite_kem08_from_private_bytes(
                    algorithm=vector.name, private_key=vector.dk_bytes
                )
                self.assertIsInstance(private_key, CompositeKEM08PrivateKey)
                self.assertIsInstance(private_key.pq_key, MLKEMPrivateKey)
                self.assertIsInstance(private_key.trad_key, DHKEMPrivateKey)
                self.assertEqual(private_key.pq_key.name, PQKeyFactory.get_pq_alg_name(vector.name))
                ss_out = private_key.decaps(vector.ct_bytes)
                self.assertEqual(ss_out.hex(), vector.ss.hex())

    def test_decaps_composite_x_key(self):
        """
        GIVEN a Composite KEM draft-08 test vector with X25519/X448 keys,
        WHEN the key is loaded from bytes,
        THEN it should match the expected values.
        """
        for vector in self.test_vectors:
            if "X25519" not in vector.tcId and "X448" not in vector.tcId:
                continue

            with self.subTest(tcId=vector.tcId):
                private_key = _load_composite_kem08_from_private_bytes(
                    algorithm=vector.name, private_key=vector.dk_bytes
                )
                self.assertIsInstance(private_key, CompositeKEM08PrivateKey)
                self.assertIsInstance(private_key.pq_key, MLKEMPrivateKey)
                self.assertIsInstance(private_key.trad_key, DHKEMPrivateKey)
                ss_out = private_key.decaps(vector.ct_bytes)
                self.assertEqual(ss_out.hex(), vector.ss.hex())


if __name__ == "__main__":
    unittest.main()
