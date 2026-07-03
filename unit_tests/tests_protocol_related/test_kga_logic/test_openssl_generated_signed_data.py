# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Validate `SignedData` structures which were generated with the OpenSSL command line tool.

The fixtures inside `data/openssl_cms` were created by an independent CMS
implementation (OpenSSL), so these tests cross-check that the `SignedData` validation
logic accepts correct structures it did not build itself. The generation commands are
documented in `data/openssl_cms/README.md`.
"""

import os
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc5652, rfc5958
from resources.ca_kga_logic import validate_signed_data_structure
from resources.envdatautils import prepare_asymmetric_key_package
from resources.keyutils import generate_key, load_private_key_from_file

FIXTURE_DIR = "data/openssl_cms"

EC_FIXTURE = os.path.join(FIXTURE_DIR, "signed_data_ecdsa.der")
ML_DSA_FIXTURE = os.path.join(FIXTURE_DIR, "signed_data_ml_dsa_65.der")
SLH_DSA_FIXTURE = os.path.join(FIXTURE_DIR, "signed_data_slh_dsa_sha2_256f.der")

_NOT_UPLOADED = "The OpenSSL-generated fixture `%s` is not present."


def _load_signed_data(path: str) -> rfc5652.SignedData:
    """Load an OpenSSL-generated CMS DER file and extract the `SignedData` structure.

    :param path: The path to the DER-encoded `ContentInfo` file.
    :return: The decoded `SignedData` structure.
    :raises ValueError: If the decoding has a remainder or the content type is not id-signedData.
    """
    with open(path, "rb") as cms_file:
        der_data = cms_file.read()

    content_info, rest = decoder.decode(der_data, asn1Spec=rfc5652.ContentInfo())
    if rest != b"":
        raise ValueError("The decoding of the `ContentInfo` structure had a remainder!")

    if content_info["contentType"] != rfc5652.id_signedData:
        raise ValueError("The `contentType` of the `ContentInfo` structure must be id-signedData!")

    signed_data, rest = decoder.decode(content_info["content"], asn1Spec=rfc5652.SignedData())
    if rest != b"":
        raise ValueError("The decoding of the `SignedData` structure had a remainder!")

    return signed_data


class TestOpenSSLGeneratedSignedData(unittest.TestCase):
    """Validate `SignedData` structures created by the OpenSSL command line tool."""

    @classmethod
    def setUpClass(cls):
        cls.transported_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        with open(os.path.join(FIXTURE_DIR, "akp_rsa.der"), "rb") as akp_file:
            cls.akp_der = akp_file.read()

    def _check_openssl_structure(self, signed_data: rfc5652.SignedData) -> None:
        """Check the OpenSSL output itself, so a failure pinpoints which side diverged."""
        self.assertEqual(int(signed_data["version"]), 3)
        self.assertEqual(len(signed_data["digestAlgorithms"]), 1)
        self.assertEqual(
            signed_data["encapContentInfo"]["eContentType"],
            rfc5958.id_ct_KP_aKeyPackage,
        )
        self.assertEqual(signed_data["encapContentInfo"]["eContent"].asOctets(), self.akp_der)
        self.assertEqual(len(signed_data["signerInfos"]), 1)
        self.assertEqual(signed_data["signerInfos"][0]["sid"].getName(), "subjectKeyIdentifier")

    def _validate_fixture(self, path: str, trustanchors: str) -> None:
        """Validate an OpenSSL-generated fixture and the extracted private key."""
        signed_data = _load_signed_data(path)
        self._check_openssl_structure(signed_data)
        private_key = validate_signed_data_structure(signed_data, trustanchors=trustanchors)
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertEqual(private_key.public_key(), self.transported_key.public_key())

    @unittest.skipUnless(os.path.isfile(EC_FIXTURE), _NOT_UPLOADED % EC_FIXTURE)
    def test_openssl_signed_data_ecdsa(self):
        """
        GIVEN a SignedData structure created by OpenSSL, signed with the ECDSA KGA certificate.
        WHEN validate_signed_data_structure is called,
        THEN the structure is accepted and the extracted private key matches the packaged RSA key.
        """
        self._validate_fixture(EC_FIXTURE, trustanchors="data/unittest")

    @unittest.skipUnless(os.path.isfile(ML_DSA_FIXTURE), _NOT_UPLOADED % ML_DSA_FIXTURE)
    def test_openssl_signed_data_ml_dsa_65(self):
        """
        GIVEN a SignedData structure created by OpenSSL, signed with an ML-DSA-65 KGA certificate.
        WHEN validate_signed_data_structure is called,
        THEN the structure is accepted and the extracted private key matches the packaged RSA key.
        """
        self._validate_fixture(ML_DSA_FIXTURE, trustanchors=os.path.join(FIXTURE_DIR, "trustanchors"))

    @unittest.skipUnless(os.path.isfile(SLH_DSA_FIXTURE), _NOT_UPLOADED % SLH_DSA_FIXTURE)
    def test_openssl_signed_data_slh_dsa_sha2_256f(self):
        """
        GIVEN a SignedData structure created by OpenSSL, signed with an SLH-DSA-SHA2-256f KGA certificate.
        WHEN validate_signed_data_structure is called,
        THEN the structure is accepted and the extracted private key matches the packaged RSA key.
        """
        self._validate_fixture(SLH_DSA_FIXTURE, trustanchors=os.path.join(FIXTURE_DIR, "trustanchors"))

    @unittest.skipUnless(os.path.isfile(EC_FIXTURE), _NOT_UPLOADED % EC_FIXTURE)
    def test_openssl_signed_data_with_tampered_e_content(self):
        """
        GIVEN an OpenSSL-generated SignedData structure whose eContent was replaced after signing.
        WHEN validate_signed_data_structure is called,
        THEN a ValueError is raised, because the messageDigest does not match the eContent.
        """
        signed_data = _load_signed_data(EC_FIXTURE)
        other_akp = prepare_asymmetric_key_package(private_keys=[generate_key("rsa")])
        signed_data["encapContentInfo"]["eContent"] = encoder.encode(other_akp)

        with self.assertRaises(ValueError):
            validate_signed_data_structure(signed_data, trustanchors="data/unittest")


if __name__ == "__main__":
    unittest.main()
