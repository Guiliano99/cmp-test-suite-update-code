# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for handling keys in PyASN1 format."""

import os
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from robot.api.deco import not_keyword

from pq_logic.keys.abstract_wrapper_keys import PQPrivateKey
from pq_logic.keys.xwing import XWingPrivateKey

RawKeyType = Union[
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
    XWingPrivateKey,
    PQPrivateKey,
]


def compute_aes_cbc(key: bytes, data: bytes, iv: bytes, decrypt: bool = True) -> bytes:
    """Perform AES encryption or decryption in CBC mode.

    :param key: The AES key to be used for encryption/decryption.
    :param data: The plaintext (for encryption) or ciphertext (for decryption).
    :param iv: The initialization vector (IV) to be used in CBC mode.
    :param decrypt: A boolean indicating whether to decrypt (True) or encrypt (False).
    :return: The encrypted or decrypted data as bytes.
    :raises ValueError: If the key size is invalid or the input data is not a multiple of the block size.
    """
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long for AES-CBC.")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    if decrypt:
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()

        # Remove padding after decryption
        unpadder = aes_padding.PKCS7(algorithms.AES.block_size).unpadder()  # type: ignore
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data

    # Apply padding before encryption
    padder = aes_padding.PKCS7(algorithms.AES.block_size).padder()  # type: ignore
    padded_data = padder.update(data) + padder.finalize()

    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


supported_keys = [
    b"X25519",
    b"X448",
    b"ED25519",
    b"ED448",
    b"RSA",
    b"EC",
]

CUSTOM_KEY_TYPES = [
    b"SNTRUP761",
    b"McEliece",
    b"SLH-DSA",
    b"COMPOSITE-SIG",
    b"COMPOSITE-KEM",
    b"COMPOSITE-DHKEM",
    b"FrodoKEM",
    b"XWING",
    b"ML-DSA",
    b"ML-KEM",
    b"RSA-KEM",
    b"CHEMPAT",
    b"BASE",
    b"PQ",
    b"XMSS",
    b"XMSSMT",
    b"HSS",
]

supported_keys += CUSTOM_KEY_TYPES


@not_keyword
def load_enc_key(password: str, data: bytes) -> bytes:
    """Load PEM formatted encrypted key.

    :param password: Password for decryption.
    :param data: PEM encoded encrypted key (PKCS#8 ``-----BEGIN ENCRYPTED PRIVATE KEY-----`` format).
    :return: The decrypted key in DER-encoded `OneAsymmetricKey` bytes.
    """
    from resources.cryptoutils import decrypt_private_key_pkcs8

    return decrypt_private_key_pkcs8(encrypted_pem=data, password=password)


@not_keyword
def derive_and_encrypt_key(
    password: str, data: bytes, decrypt: bool, iv: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """Derive an encryption key using PBKDF2 and encrypts data using AES-CBC.

    :param password: Password to derive the encryption key.
    :param data: Data to encrypt.
    :param decrypt: Whether to decrypt or encrypt the data.
    :param iv: Optional initialization vector (IV). If None, a random IV is generated.
    :return: Tuple of (enc_data, iv).
    """
    if iv is None and decrypt:
        raise ValueError("For decryption must a `iv` be parsed.")

    if iv is None:
        iv = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=iv,
        iterations=100_000,
    )
    enc_key = kdf.derive(password.encode("utf-8"))

    enc_data = compute_aes_cbc(key=enc_key, data=data, iv=iv, decrypt=decrypt)

    return enc_data, iv
