# SPDX-FileCopyrightText: 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Decrypt or re-encrypt all PEM private keys stored under ``data/keys/``.

The script operates on the main ``data/keys/`` directory as well as the subdirectories listed in data/keys.

Usage (run from the repository root):
    # Strip encryption from every key file
    python scripts/decrypt_keys.py

    # Re-encrypt every key file currently stored in plain text
    python scripts/decrypt_keys.py --encrypt
"""

import argparse
import glob
import logging
import os
import sys
from typing import Tuple

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

sys.path.append(".")

from resources.keyutils import (  # pylint: disable=import-error,wrong-import-position  # noqa: E402
    load_private_key_from_file,
    save_key,
)
from resources.suiteenums import KeySaveType  # pylint: disable=import-error,wrong-import-position  # noqa: E402

KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "keys")
OTHER_DIRS = ["hss_keys", "xmss_xmssmt_keys", "xmss_xmssmt_keys_verbose"]
DEFAULT_PASSWORD = "11111"


def _get_all_pem_files() -> list[str]:
    """Return sorted paths to every ``.pem`` file that should be processed.

    :return: Sorted list of absolute ``.pem`` file paths.
    """
    pem_files = sorted(glob.glob(os.path.join(KEYS_DIR, "*.pem")))
    for name in OTHER_DIRS:
        sub_dir = os.path.join(KEYS_DIR, name)
        extra = glob.glob(os.path.join(sub_dir, "*.pem"))
        logging.debug("Found %d .pem files in %s", len(extra), sub_dir)
        pem_files.extend(extra)
    return pem_files


def _get_save_type_and_format(filepath: str) -> Tuple[KeySaveType, bool]:
    """Decide what save type and format to use when re-saving or loading a key file.

    :param filepath: Absolute path to the PEM key file.
    :return: A ``(save_type, save_old)`` tuple where *save_old* is ``True``
     when the filename contains ``"seed-old"``, and *save_type* is set to `RAW`,
     if the filename contains ``"raw"``.
    """
    if "seed-old" in filepath:
        return KeySaveType.SEED, True
    if "raw" in filepath:
        return KeySaveType.RAW, False
    return KeySaveType.SEED, False


def decrypt_key_file(filepath: str) -> bool:
    """Remove encryption from a single PEM key file and write it back to disk.

    :param filepath: Absolute path to the PEM key file.
    :return: ``True`` if the file was decrypted and written; ``False`` if the file was already
    unencrypted and was therefore skipped.
    """
    with open(filepath, "rb") as fh:
        if b"ENCRYPTED" not in fh.read():
            return False

    save_type, save_old = _get_save_type_and_format(filepath)
    key = load_private_key_from_file(filepath, password=DEFAULT_PASSWORD)
    save_key(key, filepath, password=None, save_old=save_old, save_type=save_type.value)
    return True


def _resave_unencrypted_key_file(filepath: str) -> bool:
    """Encrypt a plain-text PEM key file and write it back to disk.

    :param filepath: Absolute path to the PEM key file.
    :return: ``True`` if the file was encrypted and written; ``False`` if it was skipped.
    """
    if "private-key-rsa.pem" in filepath:
        return False

    with open(filepath, "rb") as fh:
        if b"ENCRYPTED" in fh.read():
            return False

    save_type, save_old = _get_save_type_and_format(filepath)
    key = load_private_key_from_file(filepath, password=None)
    save_key(key, filepath, password=DEFAULT_PASSWORD, save_old=save_old, save_type=save_type.value)
    return True


def decrypt_all_files() -> None:
    """Strip encryption from every PEM key file inside data/keys/* and its subdirectories.

    Files that are already stored without encryption are skipped.
    """
    pem_files = _get_all_pem_files()
    if not pem_files:
        logging.error("No .pem files found in %s", KEYS_DIR)
        sys.exit(1)

    processed = 0
    for fp in pem_files:
        if decrypt_key_file(fp):
            logging.debug("Decrypted: %s", os.path.basename(fp))
            processed += 1

    logging.debug("Done — %d key(s) decrypted, %d skipped.", processed, len(pem_files) - processed)


def encrypt_all_files() -> None:
    """Encrypt every plain-text PEM key file inside data/keys/* and its subdirectories.

    Files that are already encrypted, or the ``"private-key-rsa.pem" file, are skipped.
    """
    pem_files = _get_all_pem_files()
    if not pem_files:
        logging.error("No .pem files found in %s", KEYS_DIR)
        sys.exit(1)

    processed = 0
    for fp in pem_files:
        if _resave_unencrypted_key_file(fp):
            logging.debug("Re-saved: %s", os.path.basename(fp))
            processed += 1

    logging.debug("Done — %d key(s) re-saved, %d skipped.", processed, len(pem_files) - processed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt or re-encrypt PEM private key files under data/keys/.")
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Re-encrypt all PEM key files that are currently stored without encryption.",
    )
    parsed = parser.parse_args()
    if parsed.encrypt:
        encrypt_all_files()
    else:
        decrypt_all_files()
