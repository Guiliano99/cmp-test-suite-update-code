# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import base64
import unittest
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key

from pq_logic.keys.composite_kem10 import CompositeKEM10PrivateKey, CompositeKEM10PublicKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pq_logic.keys.trad_kem_keys import DHKEMPrivateKey, RSADecapKey, RSAEncapKey
from resources.certutils import parse_certificate
from resources.exceptions import InvalidKeyData
from resources.oidutils import CURVE_NAMES_TO_INSTANCES


COMPOSITE_KEM10_ORIGINAL_NAME_TO_NAME = {
    "id-MLKEM768-RSA3072-SHA3-256": "composite-kem10-ml-kem-768-rsa3072",
    "id-MLKEM768-RSA4096-SHA3-256": "composite-kem10-ml-kem-768-rsa4096",
    "id-MLKEM768-RSA2048-SHA3-256": "composite-kem10-ml-kem-768-rsa2048",
    "id-MLKEM768-X25519-SHA3-256": "composite-kem10-ml-kem-768-x25519",
    "id-MLKEM768-ECDH-P256-SHA3-256": "composite-kem10-ml-kem-768-ecdh-secp256r1",
    "id-MLKEM768-ECDH-P384-SHA3-256": "composite-kem10-ml-kem-768-ecdh-secp384r1",
    "id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256": "composite-kem10-ml-kem-768-ecdh-brainpoolP256r1",
    "id-MLKEM1024-RSA3072-SHA3-256": "composite-kem10-ml-kem-1024-rsa3072",
    "id-MLKEM1024-ECDH-P384-SHA3-256": "composite-kem10-ml-kem-1024-ecdh-secp384r1",
    "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256": "composite-kem10-ml-kem-1024-ecdh-brainpoolP384r1",
    "id-MLKEM1024-X448-SHA3-256": "composite-kem10-ml-kem-1024-x448",
    "id-MLKEM1024-ECDH-P521-SHA3-256": "composite-kem10-ml-kem-1024-ecdh-secp521r1",
}


@dataclass
class CompositeKEM10TestVectors:
    """
    Test vectors for Composite KEM 1.0.
    """

    tcId: str
    ek: str
    x5c: str
    dk: str
    dk_pkcs8: str
    c: str
    k: str

    @classmethod
    def from_dict(cls, data: dict) -> "CompositeKEM10TestVectors":
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
        return COMPOSITE_KEM10_ORIGINAL_NAME_TO_NAME[self.tcId]

    @property
    def ct_bytes(self):
        """Get the ciphertext as bytes."""
        return base64.b64decode(self.c)


def _load_composite_kem10_from_private_bytes(algorithm: str, private_key: bytes) -> CompositeKEM10PrivateKey:
    """
    Load a Composite KEM v10 public key from private key bytes.

    :param algorithm: The name of the algorithm.
    :param private_key: The private key bytes.
    :return: A CompositeKEM10PublicKey instance.
    """
    algorithm = algorithm.lower()
    prefix = "composite-kem10-"
    pq_name = PQKeyFactory.get_pq_alg_name(algorithm=algorithm)
    tmp_pq_key = PQKeyFactory.generate_pq_key(pq_name)

    if hasattr(tmp_pq_key, "private_numbers"):
        seed_size = len(tmp_pq_key.private_numbers())
    else:
        seed_size = len(tmp_pq_key.private_bytes_raw())

    pq_data = private_key[:seed_size]
    pq_key = tmp_pq_key.from_private_bytes(pq_data, name=pq_name)
    trad_bytes = private_key[seed_size:]

    trad_name = algorithm.replace(prefix, "").replace(pq_name + "-", "")
    if trad_name == "x25519":
        trad_key = X25519PrivateKey.from_private_bytes(trad_bytes)
    elif trad_name == "x448":
        trad_key = X448PrivateKey.from_private_bytes(trad_bytes)
    elif trad_name.startswith("ecdh-"):
        curve_name = trad_name.replace("ecdh-", "")
        curve = CURVE_NAMES_TO_INSTANCES.get(curve_name)
        if curve is None:
            raise ValueError(f"Unsupported ECDH curve: {curve_name}")
        trad_key = load_der_private_key(trad_bytes, password=None)
        if trad_key.curve.name.lower() != curve_name.lower():
            raise InvalidKeyData(f"Expected ECDH curve {curve_name}, but got {trad_key.curve.name}")

    elif trad_name.startswith("rsa"):
        num = int(trad_name.replace("rsa", ""))
        trad_key = load_der_private_key(trad_bytes, password=None)
        if trad_key.key_size != num:
            raise InvalidKeyData(f"Expected RSA key size {num}, but got {trad_key.key_size}")

    else:
        raise ValueError(f"Unsupported traditional key type: {trad_name}")

    if not isinstance(trad_key, rsa.RSAPrivateKey):
        trad_key = DHKEMPrivateKey(private_key=trad_key, use_rfc9180=False)

    return CompositeKEM10PrivateKey(
        pq_key=pq_key,
        trad_key=trad_key,
    )


def _load_composite_kem10_from_public_bytes(algorithm: str, public_key: bytes) -> CompositeKEM10PublicKey:
    """Load a Composite KEM v10 public key from public bytes.

    :param algorithm: The name of the algorithm.
    :param public_key: The public key bytes.
    :return: A CompositeKEM10PublicKey instance.
    """
    algorithm = algorithm.lower()
    prefix = "composite-kem10-"
    pq_name = PQKeyFactory.get_pq_alg_name(algorithm=algorithm)
    trad_name = algorithm.replace(prefix, "").replace(pq_name + "-", "")
    pq_key, rest = PQKeyFactory.from_public_bytes(pq_name, public_key, allow_rest=True)

    if trad_name == "x25519":
        trad_key = X25519PublicKey.from_public_bytes(rest)
    elif trad_name == "x448":
        trad_key = X448PublicKey.from_public_bytes(rest)
    elif trad_name == "ecdh":
        curve_name = trad_name.replace("ecdh-", "")
        curve = CURVE_NAMES_TO_INSTANCES.get(curve_name)
        if curve is None:
            raise ValueError(f"Unsupported ECDH curve: {curve_name}")
        trad_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, rest)
    elif trad_name == "rsa":
        trad_key = load_der_public_key(rest)
        trad_key = RSAEncapKey(trad_key)
    else:
        raise ValueError(f"Unsupported traditional key type: {trad_name}")

    return CompositeKEM10PublicKey(
        pq_key=pq_key,
        trad_key=trad_key,
    )


class TestCompositeKEM10TestVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = "./data/rfc_test_vectors/composite_kem10_testvectors.json"
        cls.test_vectors = cls.load_test_vectors(cls.path)
        if len(cls.test_vectors) == 0:
            raise ValueError("No test vectors loaded.")
        if len(cls.test_vectors) != 12:
            cls._display_orig_names()
            raise ValueError(f"The number of Composite KEM v10 test vectors is not as expected. Got: {len(cls.test_vectors)}")

    @classmethod
    def _display_orig_names(cls) -> None:
        """Display the original names of the test vectors."""
        for vector in cls.test_vectors:
            print(f"{vector.tcId}")

    @staticmethod
    def load_test_vectors(path: str) -> list[CompositeKEM10TestVectors]:
        import json

        with open(path, "r") as file:
            data = json.load(file)

        tests_vectors = []
        for test in data["tests"]:
            if test["tcId"] in ["id-alg-ml-kem-768", "id-alg-ml-kem-1024"]:
                continue
            tests_vectors.append(CompositeKEM10TestVectors.from_dict(test))

        return tests_vectors

    def test_decaps_composite_rsa_key(self):
        """
        GIVEN a Composite KEM v10 test vector with RSA keys,
        WHEN the key is loaded from bytes,
        THEN it should match the expected values.
        """
        for vector in self.test_vectors:
            if "RSA" not in vector.tcId:
                continue

            with self.subTest(tcId=vector.tcId):
                private_key = _load_composite_kem10_from_private_bytes(
                    algorithm=vector.name, private_key=vector.dk_bytes
                )
                self.assertIsInstance(private_key, CompositeKEM10PrivateKey)
                self.assertIsInstance(private_key.pq_key, MLKEMPrivateKey)
                self.assertIsInstance(private_key.trad_key, RSADecapKey)
                self.assertEqual(private_key.pq_key.name, PQKeyFactory.get_pq_alg_name(vector.name))
                ss_out = private_key.decaps(vector.ct_bytes)
                self.assertEqual(ss_out.hex(), vector.ss.hex())

    def test_decaps_composite_ecdh_key(self):
        """
        GIVEN a Composite KEM v10 test vector with ECDH keys,
        WHEN the key is loaded from bytes,
        THEN it should match the expected values.
        """
        for vector in self.test_vectors:
            if "ECDH" not in vector.tcId:
                continue

            with self.subTest(tcId=vector.tcId):
                private_key = _load_composite_kem10_from_private_bytes(
                    algorithm=vector.name, private_key=vector.dk_bytes
                )
                self.assertIsInstance(private_key, CompositeKEM10PrivateKey)
                self.assertIsInstance(private_key.pq_key, MLKEMPrivateKey)
                self.assertIsInstance(private_key.trad_key, DHKEMPrivateKey)
                self.assertEqual(private_key.pq_key.name, PQKeyFactory.get_pq_alg_name(vector.name))
                ss_out = private_key.decaps(vector.ct_bytes)
                self.assertEqual(ss_out.hex(), vector.ss.hex())

    def test_decaps_composite_x_key(self):
        """
        GIVEN a Composite KEM v10 test vector with X25519/X448 keys,
        WHEN the key is loaded from bytes,
        THEN it should match the expected values.
        """
        for vector in self.test_vectors:
            if "X25519" not in vector.tcId and "X448" not in vector.tcId:
                continue

            with self.subTest(tcId=vector.tcId):
                private_key = _load_composite_kem10_from_private_bytes(
                    algorithm=vector.name, private_key=vector.dk_bytes
                )
                self.assertIsInstance(private_key, CompositeKEM10PrivateKey)
                self.assertIsInstance(private_key.pq_key, MLKEMPrivateKey)
                self.assertIsInstance(private_key.trad_key, DHKEMPrivateKey)
                ss_out = private_key.decaps(vector.ct_bytes)
                self.assertEqual(ss_out.hex(), vector.ss.hex())


if __name__ == "__main__":
    unittest.main()
