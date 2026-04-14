# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for handling keys in PyASN1 format."""

import base64
import os
import textwrap

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3565, rfc5208, rfc8018, rfc9480
from robot.api.deco import not_keyword

from resources import prepare_alg_ids


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
def encrypt_private_key_pkcs8(
    private_key_der: bytes,
    password: str | bytes,
    iterations: int = 600000,
    salt_length: int = 16,
    iv_length: int = 16,
) -> bytes:
    """Encrypt a DER-encoded private key using PKCS#8 with PBKDF2 and AES-256-CBC.

    Uses RFC structures:
    - RFC 5208: PKCS#8 (EncryptedPrivateKeyInfo)
    - RFC 8018: PBES2, PBKDF2

    :param private_key_der: DER-encoded private key (OneAsymmetricKey / PrivateKeyInfo).
    :param password: Password for encryption (bytes or UTF-8 string).
    :param iterations: PBKDF2 iteration count. Defaults to 600000.
    :param salt_length: Salt length in bytes. Defaults to 16.
    :param iv_length: IV length in bytes. Defaults to 16.
    :return: DER-encoded EncryptedPrivateKeyInfo.
    :raises ValueError: If inputs are invalid.
    """
    if isinstance(password, str):
        password = password.encode("utf-8")

    if not password:
        raise ValueError("Password must not be empty.")

    if iv_length != 16:
        raise ValueError("IV length must be 16 bytes for AES-CBC.")

    salt = os.urandom(salt_length)
    iv = os.urandom(iv_length)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    encryption_key = kdf.derive(password)

    encrypted_key = compute_aes_cbc(key=encryption_key, data=private_key_der, iv=iv, decrypt=False)

    kdf_alg_id = prepare_alg_ids.prepare_pbkdf2_alg_id(
        salt=salt, iterations=iterations, key_length=32, hash_alg="sha256"
    )

    enc_scheme = rfc9480.AlgorithmIdentifier()
    enc_scheme["algorithm"] = rfc3565.id_aes256_CBC
    enc_scheme["parameters"] = univ.OctetString(iv)

    pbes2_params = rfc8018.PBES2_params()
    pbes2_params["keyDerivationFunc"] = kdf_alg_id
    pbes2_params["encryptionScheme"] = enc_scheme

    pbes2_alg_id = rfc9480.AlgorithmIdentifier()
    pbes2_alg_id["algorithm"] = rfc8018.id_PBES2
    pbes2_alg_id["parameters"] = pbes2_params

    encrypted_private_key_info = rfc5208.EncryptedPrivateKeyInfo()
    encrypted_private_key_info["encryptionAlgorithm"] = pbes2_alg_id
    encrypted_private_key_info["encryptedData"] = univ.OctetString(encrypted_key)

    return encoder.encode(encrypted_private_key_info)


@not_keyword
def encrypt_private_key_pkcs8_pem(
    private_key_der: bytes,
    password: str | bytes,
    iterations: int = 600000,
    salt_length: int = 16,
    iv_length: int = 16,
) -> bytes:
    """Encrypt a DER-encoded private key and return PEM-encoded ENCRYPTED PRIVATE KEY.

    :param private_key_der: DER-encoded private key (OneAsymmetricKey / PrivateKeyInfo).
    :param password: Password for encryption (bytes or UTF-8 string).
    :param iterations: PBKDF2 iteration count. Defaults to 600000.
    :param salt_length: Salt length in bytes. Defaults to 16.
    :param iv_length: IV length in bytes. Defaults to 16.
    :return: PEM-encoded encrypted private key.
    """
    encrypted_der = encrypt_private_key_pkcs8(
        private_key_der=private_key_der,
        password=password,
        iterations=iterations,
        salt_length=salt_length,
        iv_length=iv_length,
    )
    pem_data = base64.b64encode(encrypted_der).decode("ascii")
    pem_body = "\n".join(textwrap.wrap(pem_data, 64))
    pem = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{pem_body}\n-----END ENCRYPTED PRIVATE KEY-----\n"
    return pem.encode("ascii")


@not_keyword
def decrypt_private_key_pkcs8(
    encrypted_der: bytes,
    password: str | bytes,
) -> bytes:
    """Decrypt a DER-encoded EncryptedPrivateKeyInfo (PKCS#8 PBES2/PBKDF2/AES-256-CBC).

    :param encrypted_der: DER-encoded EncryptedPrivateKeyInfo.
    :param password: Password for decryption (bytes or UTF-8 string).
    :return: The decrypted DER-encoded private key (OneAsymmetricKey / PrivateKeyInfo).
    :raises ValueError: If the structure is not valid or the algorithm is unsupported.
    """
    if isinstance(password, str):
        password = password.encode("utf-8")

    enc_pki, rest = decoder.decode(encrypted_der, asn1Spec=rfc5208.EncryptedPrivateKeyInfo())
    if rest:
        raise ValueError("Trailing data after EncryptedPrivateKeyInfo.")

    enc_alg = enc_pki["encryptionAlgorithm"]
    if enc_alg["algorithm"] != rfc8018.id_PBES2:
        raise ValueError(f"Unsupported encryption algorithm: {enc_alg['algorithm']}. Expected PBES2.")

    pbes2_params, _ = decoder.decode(enc_alg["parameters"], asn1Spec=rfc8018.PBES2_params())

    # Extract KDF parameters
    kdf_alg = pbes2_params["keyDerivationFunc"]
    if kdf_alg["algorithm"] != rfc8018.id_PBKDF2:
        raise ValueError(f"Unsupported KDF: {kdf_alg['algorithm']}. Expected PBKDF2.")

    pbkdf2_params, _ = decoder.decode(kdf_alg["parameters"], asn1Spec=rfc8018.PBKDF2_params())

    salt = bytes(pbkdf2_params["salt"]["specified"])
    iterations = int(pbkdf2_params["iterationCount"])
    key_length = int(pbkdf2_params["keyLength"]) if pbkdf2_params["keyLength"].isValue else 32

    # Extract encryption scheme parameters
    enc_scheme = pbes2_params["encryptionScheme"]
    if enc_scheme["algorithm"] != rfc3565.id_aes256_CBC:
        raise ValueError(f"Unsupported encryption scheme: {enc_scheme['algorithm']}. Expected AES-256-CBC.")

    iv_asn1, _ = decoder.decode(enc_scheme["parameters"], asn1Spec=univ.OctetString())
    iv = bytes(iv_asn1)

    # Derive the key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
    )
    decryption_key = kdf.derive(password)

    # Decrypt
    encrypted_data = bytes(enc_pki["encryptedData"])
    return compute_aes_cbc(key=decryption_key, data=encrypted_data, iv=iv, decrypt=True)


@not_keyword
def decrypt_private_key_pkcs8_pem(
    pem_data: bytes,
    password: str | bytes,
) -> bytes:
    """Decrypt a PEM-encoded ENCRYPTED PRIVATE KEY (PKCS#8 format).

    :param pem_data: PEM-encoded encrypted private key.
    :param password: Password for decryption.
    :return: DER-encoded decrypted private key (OneAsymmetricKey / PrivateKeyInfo).
    """
    lines = pem_data.splitlines()
    b64_lines = []
    in_block = False
    for line in lines:
        if line.strip() == b"-----BEGIN ENCRYPTED PRIVATE KEY-----":
            in_block = True
            continue
        if line.strip() == b"-----END ENCRYPTED PRIVATE KEY-----":
            break
        if in_block:
            b64_lines.append(line.strip())

    encrypted_der = base64.b64decode(b"".join(b64_lines))
    return decrypt_private_key_pkcs8(encrypted_der, password)


@not_keyword
def load_enc_key(password: str | bytes, data: bytes) -> bytes:
    """Load and decrypt a PEM-formatted encrypted key.

    Supports two formats:
    1. PKCS#8 EncryptedPrivateKeyInfo (``BEGIN ENCRYPTED PRIVATE KEY``)
    2. Legacy Proc-Type/DEK-Info format (``BEGIN <type> PRIVATE KEY`` with DEK-Info header)

    :param password: Password for decryption (str or bytes).
    :param data: PEM encoded encrypted key.
    :return: The decrypted key in DER-encoded ``OneAsymmetricKey`` bytes.
    """
    lines = data.splitlines()

    # 1. Check the BEGIN line
    begin_line = lines[0].rstrip()

    # PKCS#8 EncryptedPrivateKeyInfo format
    if begin_line == b"-----BEGIN ENCRYPTED PRIVATE KEY-----":
        return decrypt_private_key_pkcs8_pem(data, password)

    # Legacy Proc-Type/DEK-Info format (backward compatibility)
    if not (begin_line.startswith(b"-----BEGIN ") and begin_line.endswith(b" PRIVATE KEY-----")):
        raise ValueError(f"Invalid PEM format found in first line: {begin_line}")

    # 2. Skip a line if "Proc-Type:" is present
    idx = 1
    if lines[idx].startswith(b"Proc-Type:"):
        idx += 1  # if you want, also parse it to confirm "4,ENCRYPTED"

    # 3. Check the DEK-Info line
    if not lines[idx].startswith(b"DEK-Info:"):
        raise ValueError("Missing DEK-Info header")
    dek_info_line = lines[idx]
    idx += 1

    # Parse the DEK-Info line
    _, dek_info = dek_info_line.split(b": ", 1)
    algo, iv_hex = dek_info.split(b",")
    if algo not in [b"AES-256-CBC", b"AES-192-CBC", b"AES-128-CBC"]:
        raise ValueError(f"Unsupported encryption algorithm: {algo}")
    iv = bytes.fromhex(iv_hex.decode("utf-8"))
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long")

    if idx < len(lines) and lines[idx].strip() == b"":
        idx += 1

    base64_lines = []
    while idx < len(lines):
        line = lines[idx]
        if line.startswith(b"-----END "):
            break
        base64_lines.append(line)
        idx += 1

    enc_data = base64.b64decode(b"".join(base64_lines))

    # 6. Decrypt with the legacy derive-and-encrypt function
    key_data, _ = _derive_and_encrypt_key_legacy(password=password, data=enc_data, decrypt=True, iv=iv)
    return key_data


@not_keyword
def _derive_and_encrypt_key_legacy(
    password: str | bytes, data: bytes, decrypt: bool, iv: bytes | None = None
) -> tuple[bytes, bytes]:
    """Derive an encryption key using PBKDF2 and encrypt/decrypt data using AES-CBC.

    .. deprecated::
        Legacy encryption format. Use :func:`encrypt_private_key_pkcs8` for new encryption.

    :param password: Password to derive the encryption key (str or bytes).
    :param data: Data to encrypt or decrypt.
    :param decrypt: Whether to decrypt or encrypt the data.
    :param iv: Optional initialization vector (IV). If None, a random IV is generated.
    :return: Tuple of (processed_data, iv).
    """
    if iv is None and decrypt:
        raise ValueError("For decryption an `iv` must be provided.")

    if iv is None:
        iv = os.urandom(16)

    if isinstance(password, str):
        password = password.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=iv,
        iterations=100_000,
    )
    enc_key = kdf.derive(password)

    enc_data = compute_aes_cbc(key=enc_key, data=data, iv=iv, decrypt=decrypt)

    return enc_data, iv
