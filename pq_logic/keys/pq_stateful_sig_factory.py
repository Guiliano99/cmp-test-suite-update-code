# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Factory for creating stateful post-quantum signature keys."""

import importlib.util
import logging
from typing import Dict, List, Optional, Type

from pyasn1_alt_modules import rfc5280, rfc5958

from pq_logic.keys import hss_utils
from pq_logic.keys.abstract_key_factory import AbstractKeyFactory
from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPrivateKey, PQHashStatefulSigPublicKey
from pq_logic.keys.stateful_sig_keys import (
    HSSPrivateKey,
    HSSPublicKey,
    XMSSMTPrivateKey,
    XMSSMTPublicKey,
    XMSSPrivateKey,
    XMSSPublicKey,
)
from resources import utils
from resources.oidutils import PQ_STATEFUL_HASH_SIG_OID_2_NAME
from resources.typingutils import PrivateKey

if importlib.util.find_spec("oqs") is not None:
    import oqs  # pylint: disable=import-error
else:
    logging.warning("oqs module is not installed. Some functionalities may be disabled.")
    oqs = None  # pylint: disable=invalid-name


class PQStatefulSigFactory(AbstractKeyFactory):
    """Factory class for creating stateful PQ keys."""

    _sig_prefix_2_priv_class: Dict[str, Type[PQHashStatefulSigPrivateKey]] = {
        "xmss": XMSSPrivateKey,
        "xmssmt": XMSSMTPrivateKey,
        "hss": HSSPrivateKey,
    }
    _sig_prefix_2_pub_class: Dict[str, Type[PQHashStatefulSigPublicKey]] = {
        "xmss": XMSSPublicKey,
        "xmssmt": XMSSMTPublicKey,
        "hss": HSSPublicKey,
    }

    @classmethod
    def _get_prefix(cls, name: str) -> str:
        """Return the prefix for the given algorithm."""
        for prefix in cls._sig_prefix_2_priv_class:
            if name.startswith(prefix):
                return prefix
        raise ValueError(
            f"Unsupported algorithm: {name}. Supported algorithms are: {cls.supported_algorithms()}"
        )

    @staticmethod
    def generate_key_by_name(algorithm: str) -> PrivateKey:
        """Generate a stateful PQ key based on the specified algorithm name."""
        return PQStatefulSigFactory.generate_pq_stateful_key(algorithm)

    @staticmethod
    def get_supported_keys() -> List[str]:
        """Return a list of supported stateful PQ keys."""
        return ["hss", "xmss", "xmssmt"]

    @staticmethod
    def supported_algorithms() -> list:
        """Return a list of supported stateful PQ algorithms."""
        return (
            PQStatefulSigFactory.get_algorithms_by_family()["xmss"]
            + PQStatefulSigFactory.get_algorithms_by_family()["xmssmt"]
            + PQStatefulSigFactory.get_algorithms_by_family()["hss"]
        )

    @classmethod
    def get_algorithms_by_family(cls) -> Dict[str, List[str]]:
        """Return a list of algorithms by family."""
        algorithms = []
        if oqs is not None and hasattr(oqs, "get_enabled_stateful_sig_mechanisms"):
            algorithms = oqs.get_enabled_stateful_sig_mechanisms()
            algorithms = [x.lower() for x in algorithms]

        algorithms += hss_utils.generate_hss_combinations()
        return {
            "xmss": cls._get_alg_family(algorithms, "xmss-"),
            "xmssmt": cls._get_alg_family(algorithms, "xmssmt-"),
            "hss": cls._get_alg_family(algorithms, "hss_"),
        }

    @staticmethod
    def generate_pq_stateful_key(algorithm: str, **kwargs) -> PQHashStatefulSigPrivateKey:
        """Generate a stateful PQ object based on the specified type."""
        prefix = PQStatefulSigFactory._get_prefix(algorithm)
        algorithms = PQStatefulSigFactory.supported_algorithms() + [prefix]
        if algorithm not in algorithms:
            msg = (
                f"Unsupported {prefix.upper()} algorithm: {algorithm}. "
                f"Supported algorithms are: {PQStatefulSigFactory.get_algorithms_by_family()[prefix]}"
            )
            raise ValueError(msg)

        cls = PQStatefulSigFactory._sig_prefix_2_priv_class[prefix]
        if prefix == "hss":
            return cls(algorithm, length=int(kwargs.get("length", 1)))  # type: ignore
        return cls(algorithm)  # type: ignore

    @staticmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo) -> PQHashStatefulSigPublicKey:
        """Load a public key from a SubjectPublicKeyInfo object.

        :param spki: The SubjectPublicKeyInfo object containing the public key.
        :return: An instance of the corresponding stateful signature public key class.
        """
        oid = spki["algorithm"]["algorithm"]
        public_key_bytes = spki["subjectPublicKey"].asOctets()
        algorithm = PQ_STATEFUL_HASH_SIG_OID_2_NAME[oid]
        prefix = PQStatefulSigFactory._get_prefix(algorithm)

        pub_cls = PQStatefulSigFactory._sig_prefix_2_pub_class[prefix]
        return pub_cls.from_public_bytes(public_key_bytes)  # type: ignore

    @staticmethod
    def _load_private_key_from_pkcs8(
        alg_id: rfc5280.AlgorithmIdentifier,
        private_key_bytes: bytes,
        public_key_bytes: Optional[bytes] = None,
    ) -> PQHashStatefulSigPrivateKey:
        """Load a private key from raw PKCS#8 bytes.

        :param alg_id: The AlgorithmIdentifier containing the algorithm OID.
        :param private_key_bytes: The raw bytes of the private key.
        :param public_key_bytes: Optional raw bytes of the public key.
        """
        alg_name = PQ_STATEFUL_HASH_SIG_OID_2_NAME[alg_id["algorithm"]]
        prefix = PQStatefulSigFactory._get_prefix(alg_name)
        cls = PQStatefulSigFactory._sig_prefix_2_priv_class[prefix]
        key = cls.from_private_bytes(private_key_bytes)  # type: ignore
        return cls(key.name, private_key_bytes, public_key_bytes)  # type: ignore

    @staticmethod
    def load_private_key_from_one_asym_key(one_asym_key: rfc5958.OneAsymmetricKey) -> PQHashStatefulSigPrivateKey:
        """Load a private key from a OneAsymmetricKey object.

        :param one_asym_key: The OneAsymmetricKey object containing the private key.
        :return: An instance of the corresponding stateful signature private key class.
        """
        oid = one_asym_key["privateKeyAlgorithm"]["algorithm"]
        algorithm = PQ_STATEFUL_HASH_SIG_OID_2_NAME[oid]
        public_key_bytes = None
        private_key_bytes = one_asym_key["privateKey"].asOctets()
        if one_asym_key["publicKey"].isValue:
            public_key_bytes = one_asym_key["publicKey"].asOctets()

        prefix = PQStatefulSigFactory._get_prefix(algorithm)
        if prefix == "hss":
            raise NotImplementedError(
                "HSS private key loading from OneAsymmetricKey is not implemented yet."
            )

        cls = PQStatefulSigFactory._sig_prefix_2_priv_class[prefix]
        key = cls.from_private_bytes(private_key_bytes)  # type: ignore
        if public_key_bytes:
            return cls(key.name, private_key_bytes, public_key_bytes)  # type: ignore
        return key

    @staticmethod
    def _prepare_invalid_private_key(
        private_key: PrivateKey,
    ) -> bytes:
        """Prepare an invalid private key for testing purposes."""
        private_key_bytes = private_key.private_bytes_raw()
        private_key_bytes = utils.manipulate_first_byte(private_key_bytes)
        return private_key_bytes
