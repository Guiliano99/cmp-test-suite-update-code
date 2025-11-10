import unittest

from pyasn1_alt_modules import rfc9480

from resources.certbuildutils import build_certificate, prepare_cert_template, prepare_subject_alt_name_extension
from resources.cmputils import validate_private_key_pop_statement_cert_template
from resources.keyutils import generate_key, prepare_subject_public_key_info
from resources.exceptions import BadCertTemplate


class TestValidatePrivateKeyPopStatementCertTemplate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cm = "CN=Hans the Tester"
        cls.signer_cert, cls.sign_key = build_certificate(common_name=cls.cm)
        cls.mismatching_cm = "CN=PQC Hans the Tester"
        cls.kem_key = generate_key("ml-kem-512")

    def test_validate_cert_template_success(self):
        """
        GIVEN a CertTemplate with matching subject and a non-signing (KEM) public key.
        WHEN validate_private_key_pop_statement_cert_template is called.
        THEN it should succeed without raising an exception.
        """
        spki = prepare_subject_public_key_info(self.kem_key)
        cert_template = prepare_cert_template(subject=self.cm, spki=spki)
        validate_private_key_pop_statement_cert_template(cert_template=cert_template, signer_cert=self.signer_cert)

    def test_validate_cert_template_mismatching_subject_strict(self):
        """
        GIVEN a CertTemplate whose subject differs from signer certificate.
        WHEN validation is performed with strict_subject_check=True.
        THEN BadCertTemplate with subject mismatch message is raised.
        """
        spki = prepare_subject_public_key_info(self.kem_key.public_key())
        cert_template = prepare_cert_template(subject=self.mismatching_cm, spki=spki)
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_cert_template(
                cert_template=cert_template, signer_cert=self.signer_cert, strict_subject_check=True
            )
        self.assertEqual(
            str(cm.exception),
            "The subject in the CertTemplate does not match the signer's certificate subject.",
        )

    def test_validate_cert_template_mismatching_subject_non_strict(self):
        """
        GIVEN a CertTemplate whose subject differs from signer certificate.
        WHEN validation is performed with strict_subject_check=False.
        THEN no exception is raised.
        """
        kem_key = generate_key("rsa-kem")
        spki = prepare_subject_public_key_info(kem_key)
        cert_template = prepare_cert_template(subject=self.mismatching_cm, spki=spki)
        validate_private_key_pop_statement_cert_template(
            cert_template=cert_template, signer_cert=self.signer_cert, strict_subject_check=False
        )

    def test_validate_cert_template_with_signing_key(self):
        """
        GIVEN a CertTemplate whose public key is a signing key (Ed25519/ECDSA/etc.).
        WHEN validation is performed.
        THEN BadCertTemplate indicating signing key not allowed is raised.
        """
        spki = prepare_subject_public_key_info(self.sign_key.public_key())
        cert_template = prepare_cert_template(subject=self.cm, spki=spki)
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_cert_template(cert_template=cert_template, signer_cert=self.signer_cert)
        self.assertEqual(
            str(cm.exception),
            "The PrivateKeyPossessionStatement CertTemplate public key must not be a signing key.",
        )

    def test_validate_cert_template_missing_subject(self):
        """
        GIVEN a CertTemplate with a NULL-DN subject and signer certificate not NULL-DN.
        WHEN validation is performed.
        THEN BadCertTemplate about missing subject is raised.
        """
        spki = prepare_subject_public_key_info(self.kem_key)
        cert_template = prepare_cert_template(subject="NULL-DN", spki=spki, exclude_fields="subject,validity")
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_cert_template(cert_template=cert_template, signer_cert=self.signer_cert)
        self.assertEqual(
            str(cm.exception),
            "The CertTemplate does not contain a subject, but the signer's certificate subject is not a NULL-DN.",
        )

    def test_validate_cert_template_missing_public_key(self):
        """
        GIVEN a CertTemplate without publicKey.
        WHEN validation is performed.
        THEN BadCertTemplate about missing public key is raised.
        """
        cert_template = prepare_cert_template(subject=self.cm, exclude_fields="publicKey,validity")
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_cert_template(cert_template=cert_template, signer_cert=self.signer_cert)
        self.assertEqual(
            str(cm.exception),
            "The `PrivateKeyPossessionStatement` CertTemplate must contain the public key field to validate against the signer's certificate.",
        )

    def test_cert_template_success_null_dn_with_san(self):
        """
        GIVEN a signer certificate (NULL-DN) with SAN example.com and a
        CertTemplate (NULL-DN) with matching SAN.
        WHEN validation is performed.
        THEN it succeeds without raising an exception.
        """
        san_ext = rfc9480.Extensions()
        san_ext.append(prepare_subject_alt_name_extension("example.com"))
        signer_null_dn_cert, _ = build_certificate(common_name="NULL-DN", extensions=san_ext)
        spki = prepare_subject_public_key_info(self.kem_key)
        san_template_ext = rfc9480.Extensions()
        san_template_ext.append(prepare_subject_alt_name_extension("example.com"))
        cert_template = prepare_cert_template(subject="NULL-DN", spki=spki, extensions=san_template_ext)
        validate_private_key_pop_statement_cert_template(cert_template=cert_template, signer_cert=signer_null_dn_cert)

    def test_cert_template_san_present_in_template_but_not_in_signer_null_dn(self):
        """
        GIVEN a signer certificate (NULL-DN) without SAN and a CertTemplate (NULL-DN) with SAN.
        WHEN validation is performed.
        THEN it raises BadCertTemplate indicating signer lacks SAN while template has one.
        """
        signer_no_san, _ = build_certificate(common_name="NULL-DN")
        spki = prepare_subject_public_key_info(self.kem_key)
        san_template_ext = rfc9480.Extensions()
        san_template_ext.append(prepare_subject_alt_name_extension("other.com"))
        cert_template = prepare_cert_template(subject="NULL-DN", spki=spki, extensions=san_template_ext)
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_cert_template(cert_template=cert_template, signer_cert=signer_no_san)
        self.assertEqual(
            str(cm.exception),
            "The signer's certificate does not contain a SubjectAltName extension, but the CertTemplate does.",
        )

    def test_cert_template_san_present_in_signer_but_not_in_template_null_dn(self):
        """
        GIVEN a signer certificate (NULL-DN) with SAN and a CertTemplate (NULL-DN) without SAN.
        WHEN validation is performed.
        THEN it raises BadCertTemplate indicating template lacks SAN while signer has one.
        """
        san_ext = rfc9480.Extensions()
        san_ext.append(prepare_subject_alt_name_extension("example.com"))
        signer_with_san, _ = build_certificate(common_name="NULL-DN", extensions=san_ext)
        spki = prepare_subject_public_key_info(self.kem_key)
        cert_template = prepare_cert_template(subject="NULL-DN", spki=spki)
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_cert_template(cert_template=cert_template, signer_cert=signer_with_san)
        self.assertEqual(
            str(cm.exception),
            "The CertTemplate does not contain a SubjectAltName extension, but the signer's certificate does.",
        )

    def test_cert_template_san_mismatch_both_present_null_dn(self):
        """
        GIVEN a signer certificate (NULL-DN) with SAN example.com and a CertTemplate (NULL-DN) with SAN other.com.
        WHEN validation is performed.
        THEN it raises BadCertTemplate indicating SAN value mismatch.
        """
        san_ext = rfc9480.Extensions()
        san_ext.append(prepare_subject_alt_name_extension("example.com"))
        signer_with_san, _ = build_certificate(common_name="NULL-DN", extensions=san_ext)
        spki = prepare_subject_public_key_info(self.kem_key)
        san_template_ext = rfc9480.Extensions()
        san_template_ext.append(prepare_subject_alt_name_extension("other.com"))
        cert_template = prepare_cert_template(subject="NULL-DN", spki=spki, extensions=san_template_ext)
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_cert_template(cert_template=cert_template, signer_cert=signer_with_san)
        self.assertEqual(
            str(cm.exception),
            "The SubjectAltName inside the CertTemplate does not match the signer's certificate SubjectAltName.",
        )

    def test_cert_template_both_missing_san_null_dn(self):
        """
        GIVEN a signer certificate (NULL-DN) without SAN and a CertTemplate (NULL-DN) without SAN.
        WHEN validation is performed.
        THEN it raises BadCertTemplate indicating SAN missing in both for NULL-DN subjects.
        """
        signer_no_san, _ = build_certificate(common_name="NULL-DN")
        spki = prepare_subject_public_key_info(self.kem_key)
        cert_template = prepare_cert_template(subject="NULL-DN", spki=spki)
        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_pop_statement_cert_template(cert_template=cert_template, signer_cert=signer_no_san)
        self.assertEqual(
            str(cm.exception),
            "The signer's certificate and the CertTemplate subject is a NULL-DN and the SubjectAltName is missing in both.",
        )


if __name__ == "__main__":
    unittest.main()
