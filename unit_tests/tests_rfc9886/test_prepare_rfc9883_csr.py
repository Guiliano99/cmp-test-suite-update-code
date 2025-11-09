import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509 import load_der_x509_csr
from pyasn1_alt_modules import rfc6402, rfc9481

from resources.asn1utils import encode_to_der, try_decode_pyasn1
from resources.certbuildutils import (
    build_csr,
    csr_add_attributes,
    prepare_private_key_possession_statement_attribute,
    sign_csr,
)
from resources.certutils import verify_possession_statement_signature
from resources.exceptions import BadPOP
from resources.keyutils import generate_key, load_public_key_from_spki, prepare_subject_public_key_info
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestPrepareRfc9883Csr(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer_cert, cls.sign_key = load_ca_cert_and_key()
        cls.kem_key = generate_key("rsa-kem")

    def test_build_rfc9883_csr_with_cert(self):
        """
        GIVEN a signer certificate and a KEM key with a provided signer certificate.
        WHEN build_csr is called with a private key possession statement attribute.
        THEN the returned CSR should include the attribute, and the signature should be valid.
        """
        crs_attr = prepare_private_key_possession_statement_attribute(
            signer_cert=self.signer_cert,
            include_cert=True,
        )

        spki = prepare_subject_public_key_info(self.kem_key)
        csr = build_csr(signing_key=self.sign_key, common_name="CN=Test User", spki=spki, exclude_signature=True)
        csr = csr_add_attributes(csr, crs_attr)
        csr = sign_csr(csr=csr, signing_key=self.sign_key)

        der_data = encode_to_der(csr)
        csr, tmp = try_decode_pyasn1(der_data, rfc6402.CertificationRequest())  # type: ignore
        csr: rfc6402.CertificationRequest
        self.assertEqual(tmp, b"")
        self.assertEqual(encode_to_der(csr), der_data)

        loaded_key = load_public_key_from_spki(csr["certificationRequestInfo"]["subjectPublicKeyInfo"])
        self.assertEqual(self.kem_key.public_key(), loaded_key)
        self.assertTrue(csr["signature"].isValue)
        alg_id = csr["signatureAlgorithm"]
        self.assertEqual(rfc9481.id_Ed25519, alg_id["algorithm"])

        crypto_lib_csr = load_der_x509_csr(encode_to_der(csr))
        data = crypto_lib_csr.tbs_certrequest_bytes
        signature = crypto_lib_csr.signature
        self.sign_key.public_key().verify(signature=signature, data=data)
        verify_possession_statement_signature(csr, signature_cert=self.signer_cert)

    def test_build_rfc9883_csr(self):
        """
        GIVEN a signer certificate and a KEM key.
        WHEN build_csr is called with a private key possession statement attribute.
        THEN the returned CSR should include the attribute, and the signature should be valid.
        """
        crs_attr = prepare_private_key_possession_statement_attribute(
            signer_cert=self.signer_cert,
            include_cert=True,
        )

        spki = prepare_subject_public_key_info(self.kem_key)
        csr = build_csr(signing_key=self.sign_key, common_name="CN=Test User", spki=spki, exclude_signature=True)
        csr = csr_add_attributes(csr, crs_attr)
        csr = sign_csr(csr=csr, signing_key=self.sign_key)

        loaded_key = load_public_key_from_spki(csr["certificationRequestInfo"]["subjectPublicKeyInfo"])
        self.assertEqual(self.kem_key.public_key(), loaded_key)
        self.assertTrue(csr["signature"].isValue)
        alg_id = csr["signatureAlgorithm"]
        self.assertEqual(rfc9481.id_Ed25519, alg_id["algorithm"])

        crypto_lib_csr = load_der_x509_csr(encode_to_der(csr))
        data = crypto_lib_csr.tbs_certrequest_bytes
        signature = crypto_lib_csr.signature
        self.sign_key.public_key().verify(signature=signature, data=data)
        verify_possession_statement_signature(csr)

    def _generate_other_key(self) -> Ed25519PrivateKey:
        """Generate a different Ed25519 key than the signing key."""
        for _ in range(100):
            key = generate_key("ed25519")
            if key.private_bytes_raw() != self.sign_key.private_bytes_raw():
                return key
        raise Exception("Failed to generate a different key")


    def test_build_rfc9883_csr_bad_pop(self):
        """
        GIVEN a signer certificate and a KEM key, which has a tampered possession statement certificate.
        WHEN build_csr is called with a private key possession statement attribute that is tampered.
        THEN the signature validation should fail.
        """
        crs_attr = prepare_private_key_possession_statement_attribute(
            signer_cert=self.signer_cert,
            include_cert=True,
        )
        other_key = self._generate_other_key()
        spki = prepare_subject_public_key_info(self.kem_key)
        csr = build_csr(signing_key=other_key, common_name="CN=Test User", spki=spki, exclude_signature=True)
        csr = csr_add_attributes(csr, crs_attr)
        csr = sign_csr(csr=csr, signing_key=other_key)

        der_data = encode_to_der(csr)
        csr, tmp = try_decode_pyasn1(der_data, rfc6402.CertificationRequest())  # type: ignore
        csr: rfc6402.CertificationRequest
        self.assertEqual(tmp, b"")

        with self.assertRaises(BadPOP):
            verify_possession_statement_signature(csr)

if __name__ == "__main__":
    unittest.main()
