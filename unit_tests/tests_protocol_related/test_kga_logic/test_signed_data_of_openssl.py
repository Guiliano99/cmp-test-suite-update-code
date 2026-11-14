# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from pkixutils import cms
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc5652, rfc5958
from resources.ca_kga_logic import validate_signed_data_structure
from resources.envdatautils import prepare_asymmetric_key_package
from resources.keyutils import generate_key


@unittest.skipUnless(shutil.which("openssl"), "the openssl program is not installed")
class TestSignedDataOfOpenSSL(unittest.TestCase):
    """The KGA `SignedData` of an implementation that is not this test suite."""

    def test_signed_data_of_openssl_is_accepted(self):
        """
        GIVEN a `SignedData` with an `AsymmetricKeyPackage` that `openssl cms -sign` created with the KGA key.
        WHEN validate_signed_data_structure is called.
        THEN the signature verifies and the private key is returned.

        OpenSSL computes the signature over the signed attributes, as RFC 5652 Section 5.4 requires. A test
        that only reads what this test suite built cannot tell whether the suite does the same.
        """
        new_key = generate_key("rsa")
        key_package = encoder.encode(prepare_asymmetric_key_package(private_keys=[new_key]))
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "content.der").write_bytes(key_package)
            command = ["openssl", "cms", "-sign", "-binary", "-nodetach", "-nosmimecap", "-keyid"]
            command += ["-in", str(Path(directory, "content.der")), "-outform", "DER"]
            command += ["-out", str(Path(directory, "message.der"))]
            command += ["-econtent_type", str(rfc5958.id_ct_KP_aKeyPackage), "-md", "sha256"]
            command += ["-signer", "data/unittest/kga_cert_kari_ecdsa.pem", "-inkey", "data/keys/private-key-ecdsa.pem"]
            command += ["-passin", "pass:11111"]  # the password of the test keys in data/keys
            command += ["-certfile", "data/unittest/root_cert_ed25519.pem"]
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            message = Path(directory, "message.der").read_bytes()

        content_type, content = cms.parse_cms_content_info(message)
        self.assertEqual(content_type, rfc5652.id_signedData)
        signed_data, rest = decoder.decode(content, rfc5652.SignedData())
        self.assertEqual(rest, b"")

        private_key = validate_signed_data_structure(signed_data, trustanchors="data/unittest")
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertEqual(private_key.public_key(), new_key.public_key())


if __name__ == "__main__":
    unittest.main()
