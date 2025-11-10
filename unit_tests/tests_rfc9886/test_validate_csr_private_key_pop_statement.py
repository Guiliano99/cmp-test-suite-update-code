import unittest

from resources.certbuildutils import (
    build_certificate,
    build_csr,
    csr_add_attributes,
    prepare_private_key_possession_statement_attribute,
    sign_csr,
)
from resources.cmputils import validate_csr_private_key_pop_statement
from resources.exceptions import BadCertTemplate
from resources.keyutils import generate_key, prepare_subject_public_key_info


class TestValidateCSRPrivateKeyPopStatement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cm = "CN=Hans the Tester"
        cls.signer_cert, cls.sign_key = build_certificate(common_name=cls.cm)
        cls.mismatching_cm = "CN=PQC Hans the Tester"
        cls.kem_key = generate_key("rsa-kem")

    def _prepare_csr(self, kem_key, common_name, include_cert: bool = True, bad_pop: bool = False):
        """Prepare a CSR for validation."""
        crs_attr = prepare_private_key_possession_statement_attribute(
            signer_cert=self.signer_cert,
            include_cert=include_cert,
        )

        spki = prepare_subject_public_key_info(kem_key)
        csr = build_csr(signing_key=self.sign_key, common_name=common_name, spki=spki, exclude_signature=True)
        csr = csr_add_attributes(csr, crs_attr)
        csr = sign_csr(csr=csr, signing_key=self.sign_key, bad_pop=bad_pop)
        return csr

    def test_pos_validate_csr_private_key_pop_statement_attribute(self):
        """
        GIVEN a CSR with a non-signing (KEM) public key and a matching subject.
        WHEN validate_csr_private_key_pop_statement is called.
        THEN it should succeed without raising an exception.
        """
        csr = self._prepare_csr(
            kem_key=self.kem_key,
            common_name=self.cm,
        )
        validate_csr_private_key_pop_statement(csr=csr, signer_cert=self.signer_cert, strict_subject_check=False)

    def test_pos_validate_csr_private_key_pop_statement_attribute_with_strict_subject_check(self):
        """
        GIVEN a CSR with a non-signing (KEM) public key and a matching subject.
        WHEN validate_csr_private_key_pop_statement is called with strict subject checking.
        THEN it should succeed without raising an exception.
        """
        csr = self._prepare_csr(
            kem_key=self.kem_key,
            common_name=self.cm,
        )
        validate_csr_private_key_pop_statement(csr=csr, signer_cert=self.signer_cert, strict_subject_check=True)

    def test_pos_validate_csr_private_key_pop_statement_attribute_without_cert(self):
        """
        GIVEN a CSR with a non-signing (KEM) public key and a matching subject, without including the signer cert in the attribute.
        WHEN validate_csr_private_key_pop_statement is called with strict subject checking.
        THEN it should succeed without raising an exception.
        """
        csr = self._prepare_csr(kem_key=self.kem_key, common_name=self.cm, include_cert=False)
        validate_csr_private_key_pop_statement(csr=csr, signer_cert=self.signer_cert, strict_subject_check=True)

    def test_bad_key_validate_csr_private_key_pop_statement_attribute(self):
        """
        GIVEN a CSR with a signing (Ed25519) public key.
        WHEN validate_csr_private_key_pop_statement is called.
        THEN it should raise BadCertTemplate.
        """
        csr = self._prepare_csr(generate_key("ed25519"), self.cm)
        with self.assertRaises(BadCertTemplate):
            validate_csr_private_key_pop_statement(
                csr=csr,
                signer_cert=self.signer_cert,
            )


if __name__ == "__main__":
    unittest.main()
