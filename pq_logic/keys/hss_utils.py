# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""HSS (Hierarchical Signature Scheme) utilities."""

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional

from hsslms.utils import D_MESG, cksm, coef


def u32str(x: int) -> bytes:
    """Convert an integer to a 4-byte big-endian representation."""
    return x.to_bytes(4, byteorder="big")


def u16str(x: int) -> bytes:
    """Convert an integer to a 2-byte big-endian representation."""
    return x.to_bytes(2, byteorder="big")


def u8str(x: int) -> bytes:
    """Convert an integer to a 1-byte representation."""
    return x.to_bytes(1, byteorder="big")


def hash_fn(name: str, out_len: int, *parts: bytes) -> bytes:
    """Compute a hash using the specified algorithm and return the first out_len bytes.

    :param name: Name of the hash algorithm (e.g., "sha256", "shake256").
    :param out_len: Desired output length in bytes.
    :param parts: Parts to hash together.
    :return: The computed hash as a byte string of length `out_len`.
    """
    h = hashlib.new(name)
    for p in parts:
        h.update(p)
    # SHAKE needs an explicit length
    if name.startswith("shake"):
        return h.digest(out_len)  # type: ignore
    return h.digest()[:out_len]


@dataclass
class LMOTSAlgorithmParams:
    """Dataclass for LM-OTS algorithm parameters.

    Attributes:
        hash_alg (str): Name of the hash algorithm (e.g. "sha256").
        n (int): Output length of the hash function in bytes.
        w (int): The Winternitz parameter (number of bits grouped per chain iteration).
        p (int): Number of n-byte string elements in the LM-OTS signature.
        ls (int): Number of left-shift bits used in the checksum function.
        identifier int: Optional typecode identifier for the algorithm.

    """

    hash_alg: str
    n: int
    w: int
    p: int
    ls: int
    identifier: int

    def _derive_key(self, q: int, i: int, seed_i: bytes) -> bytes:
        """Derive a single LM‑OTS key for the given parameters.

        Computes: x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xFF) || SEED_i)

        :param q: Leaf index (0 to p-1).
        :param i: Index of the key within the leaf (0 to p-1).
        :param seed_i: The seed for this leaf, derived from the master seed.
        :return: The derived key as a byte string of length n.
        """
        data = u16str(self.identifier) + u32str(q) + u16str(i) + u8str(0xFF) + seed_i
        return hash_fn(self.hash_alg, self.n, data)

    def derive_leafs(self, seed: bytes, q: int) -> List[bytes]:
        """Derive all LM‑OTS leaves for the given parameters.

        :param seed: The seed for this leaf, derived from the master seed.
        :param q: Leaf index (0 to p-1).
        :return: A list of derived keys for this leaf, each of length n.
        """
        return [self._derive_key(q, i, seed) for i in range(self.p)]

    def compute_hash(self, *args: bytes) -> bytes:
        """Compute the hash of the given arguments using the specified hash algorithm."""
        return hash_fn(self.hash_alg, self.n, *args)

    def sign(
        self,
        message: bytes,
        keys: list[bytes],
        I: bytes,  # noqa: E741
        q: int,
        c: Optional[bytes] = None,
    ) -> bytes:
        """Sign a message using the LM-OTS algorithm.

        Computes the signature for the given message and leaf index q.

        :param message: The message to sign.
        :param keys: The derived keys for this leaf.
        :param I: 16-byte identifier for the LMS key.
        :param c: Optional random bytes for the signature (if not provided, will be generated).
        :param q: Leaf index (0 to p-1).
        :return: The LM-OTS signature as a byte string.
        """
        c = c or os.urandom(self.n)
        signature = u32str(self.identifier) + c

        Q = self.compute_hash(I + u32str(q) + D_MESG + c + message)
        Qa = Q + cksm(Q, self.w, self.n, self.ls)
        for i in range(self.p):
            a = coef(Qa, i, self.w)
            tmp = keys[i]
            for j in range(a):
                tmp = self.compute_hash(I + u32str(q) + u16str(i) + u8str(j) + tmp)
            signature += tmp  # y
        return signature


LMOTS_PARAMS: Dict[str, LMOTSAlgorithmParams] = {
    # Existing SHA256/N32 parameter sets
    "lmots_sha256_n32_w1": LMOTSAlgorithmParams(hash_alg="sha256", n=32, w=1, p=265, ls=7, identifier=0x0001),
    "lmots_sha256_n32_w2": LMOTSAlgorithmParams(hash_alg="sha256", n=32, w=2, p=133, ls=6, identifier=0x0002),
    "lmots_sha256_n32_w4": LMOTSAlgorithmParams(hash_alg="sha256", n=32, w=4, p=67, ls=4, identifier=0x0003),
    "lmots_sha256_n32_w8": LMOTSAlgorithmParams(hash_alg="sha256", n=32, w=8, p=34, ls=0, identifier=0x0004),
    # SHA256/N24 parameter sets (SHA-256/192)
    "lmots_sha256_n24_w1": LMOTSAlgorithmParams(hash_alg="sha256", n=24, w=1, p=200, ls=8, identifier=0x0005),
    "lmots_sha256_n24_w2": LMOTSAlgorithmParams(hash_alg="sha256", n=24, w=2, p=101, ls=6, identifier=0x0006),
    "lmots_sha256_n24_w4": LMOTSAlgorithmParams(hash_alg="sha256", n=24, w=4, p=51, ls=4, identifier=0x0007),
    "lmots_sha256_n24_w8": LMOTSAlgorithmParams(hash_alg="sha256", n=24, w=8, p=26, ls=0, identifier=0x0008),
    # SHAKE/N32 parameter sets (SHAKE256/256)
    "lmots_shake_n32_w1": LMOTSAlgorithmParams(hash_alg="shake256", n=32, w=1, p=265, ls=7, identifier=0x0009),
    "lmots_shake_n32_w2": LMOTSAlgorithmParams(hash_alg="shake256", n=32, w=2, p=133, ls=6, identifier=0x000A),
    "lmots_shake_n32_w4": LMOTSAlgorithmParams(hash_alg="shake256", n=32, w=4, p=67, ls=4, identifier=0x000B),
    "lmots_shake_n32_w8": LMOTSAlgorithmParams(hash_alg="shake256", n=32, w=8, p=34, ls=0, identifier=0x000C),
    # SHAKE/N24 parameter sets (SHAKE256/192)
    "lmots_shake_n24_w1": LMOTSAlgorithmParams(hash_alg="shake256", n=24, w=1, p=200, ls=8, identifier=0x000D),
    "lmots_shake_n24_w2": LMOTSAlgorithmParams(hash_alg="shake256", n=24, w=2, p=101, ls=6, identifier=0x000E),
    "lmots_shake_n24_w4": LMOTSAlgorithmParams(hash_alg="shake256", n=24, w=4, p=51, ls=4, identifier=0x000F),
    "lmots_shake_n24_w8": LMOTSAlgorithmParams(hash_alg="shake256", n=24, w=8, p=26, ls=0, identifier=0x0010),
}

LMOTS_ID_2_PARAMS: Dict[int, LMOTSAlgorithmParams] = {params.identifier: params for params in LMOTS_PARAMS.values()}


def get_lmots_signature_len(lmots_sig: bytes) -> int:
    """Get the length of an LMOTS signature.

    :param lmots_sig: The LMOTS signature as a byte string.
    :return: The length of the LMOTS signature in bytes.
    """
    if len(lmots_sig) < 2:
        raise ValueError("LMOTS signature too short to extract type")
    lmots_type_code = struct.unpack(">H", lmots_sig[:2])[0]
    algo_params = LMOTS_ID_2_PARAMS.get(lmots_type_code)
    if not algo_params:
        raise ValueError(f"Missing LMOTS parameters for: {lmots_type_code}")
    return 2 + 16 + algo_params.n * algo_params.p


def _get_lms_signature_len(lms_sig: bytes) -> int:
    """Get the length of an LMS signature.

    :param lms_sig: The LMS signature as a byte string.
    :return: The length of the LMS signature in bytes.
    """
    if len(lms_sig) < 20 + 2:
        raise ValueError("LMS signature too short")
    lmots_sig_offset = 4 + 16
    lmots_sig = lms_sig[lmots_sig_offset:]
    lmots_len = get_lmots_signature_len(lmots_sig)
    auth_path_len = 15 * 32  # default, should parse from pubkey for real apps
    return 4 + 16 + lmots_len + auth_path_len


def extract_hss_leaf_index(hss_signature: bytes) -> int:
    """Extract the leaf index from an HSS signature.

    :param hss_signature: The HSS signature as a byte string.
    :return: The leaf index as an integer.
    :raises ValueError: If the signature is too short or malformed.
    """
    offset = 0
    if len(hss_signature) < 4:
        raise ValueError("Signature too short for nspk")
    nspk = struct.unpack(">I", hss_signature[offset : offset + 4])[0]
    offset += 4
    pubkey_len = 64  # default LMS pubkey length
    for _ in range(nspk - 1):
        offset += pubkey_len
        sig_len = _get_lms_signature_len(hss_signature[offset:])
        offset += sig_len
    return struct.unpack(">I", hss_signature[offset : offset + 4])[0]
