import unittest

from pyasn1_alt_modules import rfc5280, rfc9480

from resources.certbuildutils import build_certificate, build_csr, prepare_subject_alt_name_extension
from resources.cmputils import validate_private_key_pop_statement_csr
from resources.keyutils import generate_key, prepare_subject_public_key_info
from resources.exceptions import BadCertTemplate


class TestValidatePrivateKeyPopStatementCSR(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cm = "CN=Hans the Tester"
        # Build signer certificate with SAN
        san_ext = rfc9480.Extensions()
        san_ext.append(prepare_subject_alt_name_extension("example.com"))
        cls.signer_cert, cls.sign_key = build_certificate(common_name=cls.cm, extensions=san_ext)
        cls.mismatching_cm = "CN=PQC Hans the Tester"
        cls.kem_alg = "ml-kem-512"
        cls.kem_key = generate_key(cls.kem_alg)

    def test_validate_private_key_pop_statement_csr_success(self):
        """
        GIVEN a CSR with a non-signing (KEM) public key and a matching subject and SAN.
        WHEN validate_private_key_pop_statement_csr is called.
        THEN it should succeed without raising an exception.
        """
        spki = prepare_subject_public_key_info(self.kem_key)
        csr = build_csr(signing_key=self.sign_key, common_name=self.cm, spki=spki, subjectAltName="example.com")
        validate_private_key_pop_statement_csr(csr=csr, signer_cert=self.signer_cert)

    def test_validate_private_key_pop_statement_csr_null_dn_matching_san(self):
        """
        GIVEN a signer certificate with NULL-DN subject and SAN example.com, and a CSR with NULL-DN subject and matching SAN.
        WHEN validate_private_key_pop_statement_csr is called with strict subject checking.
        THEN it should succeed without raising an exception.
        """
        san_ext = rfc9480.Extensions()
        san_ext.append(prepare_subject_alt_name_extension("example.com"))
        signer_null_dn_cert, _ = build_certificate(common_name="NULL-DN", extensions=san_ext)
        spki = prepare_subject_public_key_info(self.kem_key)
        csr = build_csr(signing_key=self.sign_key, common_name="NULL-DN", spki=spki, subjectAltName="example.com")
        validate_private_key_pop_statement_csr(csr=csr, signer_cert=signer_null_dn_cert, strict_subject_check=True)

    def test_validate_private_key_pop_statement_csr_mismatching_subject_strict(self):
        """
        GIVEN a CSR whose subject differs from the signer's certificate subject.
        WHEN validate_private_key_pop_statement_csr is called with strict subject checking.
        THEN it should raise BadCertTemplate with the expected subject mismatch message.
        """
        kem_key = generate_key(self.kem_alg)
        spki = prepare_subject_public_key_info(kem_key)
        csr = build_csr(signing_key=self.sign_key, common_name=self.mismatching_cm, spki=spki, subjectAltName="example.com")
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_csr(csr=csr, signer_cert=self.signer_cert, strict_subject_check=True)
        self.assertEqual(str(cm.exception), "The subject in the CSR does not match the signer's certificate subject.")

    def test_validate_private_key_pop_statement_csr_with_signing_key(self):
        """
        GIVEN a CSR whose public key is a signing key (disallowed by RFC 9883 for this POP statement).
        WHEN validate_private_key_pop_statement_csr is called.
        THEN it should raise BadCertTemplate indicating the CSR public key must not be a signing key.
        """
        spki = prepare_subject_public_key_info(self.sign_key.public_key())
        csr = build_csr(signing_key=self.sign_key, common_name=self.cm, spki=spki, subjectAltName="example.com")
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_csr(csr=csr, signer_cert=self.signer_cert)
        self.assertEqual(str(cm.exception), "The CSR public key must not be a signing key.")

    def test_validate_csr_missing_subject(self):
        """
        GIVEN a CSR with a NULL-DN subject and a signer certificate whose subject is not a NULL-DN.
        WHEN validate_private_key_pop_statement_csr is called.
        THEN it should raise BadCertTemplate indicating a subject is required for validation.
        """
        spki = prepare_subject_public_key_info(self.kem_key.public_key())
        csr = build_csr(signing_key=self.sign_key, common_name="NULL-DN", spki=spki, subjectAltName="example.com")
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_csr(csr=csr, signer_cert=self.signer_cert)
        self.assertEqual(
            str(cm.exception),
            "The CSR does not contain a subject, but the signer's certificate subject is not a NULL-DN.",
        )

    def test_validate_private_key_pop_statement_csr_missing_public_key(self):
        """
        GIVEN a CSR with an absent subjectPublicKeyInfo field.
        WHEN validate_private_key_pop_statement_csr is called.
        THEN it should raise BadCertTemplate because the public key is missing.
        """
        csr = build_csr(signing_key=self.sign_key, common_name=self.cm, subjectAltName="example.com")
        csr["certificationRequestInfo"]["subjectPublicKeyInfo"] = rfc5280.SubjectPublicKeyInfo()
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_csr(csr=csr, signer_cert=self.signer_cert)
        self.assertEqual(
            str(cm.exception),
            "The CSR must contain the public key field to validate against the signer's certificate.",
        )

    def test_san_present_in_csr_but_not_in_signer_null_dn(self):
        """
        GIVEN a signer certificate with a NULL-DN subject and without a SubjectAltName,
        and a CSR with a NULL-DN subject and a SubjectAltName.
        WHEN validate_private_key_pop_statement_csr is called.
        THEN it should raise BadCertTemplate with the expected message about signer SAN
        set vs CSR missing (presence mismatch).
        """
        signer_no_san, _ = build_certificate(common_name="NULL-DN")
        spki = prepare_subject_public_key_info(self.kem_key)
        csr = build_csr(signing_key=self.sign_key, common_name="NULL-DN", spki=spki, subjectAltName="other.com")
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_csr(csr=csr, signer_cert=signer_no_san, strict_subject_check=True)
        self.assertEqual(
            str(cm.exception),
            "The signer's certificate does not contain a SubjectAltName extension, but the CSR does.",
        )

    def test_san_present_in_signer_but_not_in_csr_null_dn(self):
        """
        GIVEN a signer certificate with a NULL-DN subject and a SubjectAltName, and a
        CSR with a NULL-DN subject and without a SubjectAltName.
        WHEN validate_private_key_pop_statement_csr is called.
        THEN it should raise BadCertTemplate with the expected message about signer
        SAN missing vs CSR present (presence mismatch).
        """
        san_ext = rfc9480.Extensions()
        san_ext.append(prepare_subject_alt_name_extension("example.com"))
        signer_with_san, _ = build_certificate(common_name="NULL-DN", extensions=san_ext)
        spki = prepare_subject_public_key_info(self.kem_key)
        csr = build_csr(signing_key=self.sign_key, common_name="NULL-DN", spki=spki)
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_csr(csr=csr, signer_cert=signer_with_san, strict_subject_check=True)
        self.assertEqual(
            str(cm.exception),
            "The CSR does not contain a SubjectAltName extension, but the signer's certificate does.",
        )

    def test_san_mismatch_both_present_null_dn(self):
        """
        GIVEN a signer certificate with a NULL-DN subject and a SubjectAltName
        (example.com), and a CSR with a NULL-DN subject and a different SubjectAltName (other.com).
        WHEN validate_private_key_pop_statement_csr is called.
        THEN it should raise BadCertTemplate with the expected message about SAN value mismatch.
        """
        san_ext = rfc9480.Extensions()
        san_ext.append(prepare_subject_alt_name_extension("example.com"))
        signer_with_san, _ = build_certificate(common_name="NULL-DN", extensions=san_ext)
        spki = prepare_subject_public_key_info(self.kem_key)
        csr = build_csr(signing_key=self.sign_key, common_name="NULL-DN", spki=spki, subjectAltName="other.com")
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_csr(csr=csr, signer_cert=signer_with_san, strict_subject_check=True)
        self.assertEqual(
            str(cm.exception),
            "The SubjectAltName inside the CSR does not match the signer's certificate SubjectAltName.",
        )


if __name__ == "__main__":
    unittest.main()