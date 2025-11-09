import unittest
from typing import Optional

from pyasn1_alt_modules import rfc4211

from pq_logic.keys.kem_keys import MLKEMPrivateKey
from resources import certbuildutils, cmputils
from resources.certbuildutils import prepare_cert_template, prepare_issuer_and_serial_number
from resources.cmputils import (
    prepare_reginfo_private_key_possession_statement,
    prepare_signature_popo,
    validate_private_key_pop_statement_cmrf,
)
from resources.exceptions import BadCertId, BadCertTemplate, BadPOP, SignerNotTrusted
from resources.keyutils import generate_key
from resources.typingutils import PublicKey


class TestValidatePrivateKeyPopStatementCmrF(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer_cert, cls.signer_key = certbuildutils.build_certificate(common_name="CN=Hans")
        cls.signer_subject_str = "CN=Hans"  # Matches the signer cert subject.
        cls.kem_key: MLKEMPrivateKey = generate_key("ml-kem-512")
        cls.mismatch_subject_str = "CN=Mismatch"
        cls.missmatch_kem_key: MLKEMPrivateKey = generate_key("ml-kem-512")

    def _build_cert_req_msg(
            self,
            subject: str = None,
            exclude_fields: str = "validity",
            other_key: Optional[PublicKey] = None,
            poposk_input: Optional[rfc4211.POPOSigningKeyInput] = None,
            bad_pop: bool = False,
    ) -> rfc4211.CertReqMsg:
        """Helper to build a CertReqMsg with optional subject override and without publicKey if requested.

        The validate function currently raises if publicKey is present; therefore tests use exclude_public_key=True
        to exercise the non-error path. If a different subject is given, it will trigger BadCertTemplate.
        """
        subj = subject or self.signer_subject_str
        cert_template = prepare_cert_template(
            key=other_key or self.kem_key.public_key(),
            subject=subj,
            exclude_fields=exclude_fields,
            include_cert_extensions=False,
        )

        poposk_input = poposk_input or cmputils.prepare_poposigningkeyinput(
            public_key=other_key or self.kem_key.public_key(),
            sender=subj,
        )

        cert_request = cmputils.prepare_cert_request(
            key=other_key or self.signer_key.public_key(),
            cert_template=cert_template,
            common_name=subj,  # only used if cert_template were None
        )
        # Prepare POPOSigningKey with poposkInput (sender must match subject for success cases)
        popo = prepare_signature_popo(
            signing_key=self.signer_key,
            cert_request=cert_request,
            poposk_input=poposk_input,
            bad_pop=bad_pop,
            sign_poposk_input=True,
        )
        cert_req_msg = rfc4211.CertReqMsg()
        cert_req_msg["certReq"] = cert_request
        cert_req_msg["popo"] = popo
        return cert_req_msg

    def _add_reginfo_statement(
            self,
            cert_req_msg: rfc4211.CertReqMsg,
            *,
            signer_cert=None,
            include_cert=True,
            modify_serial=False,
            modify_issuer=False,
    ) -> rfc4211.CertReqMsg:
        """Attach a PrivateKeyPossessionStatement attribute to the regInfo field."""
        signer_cert = signer_cert or self.signer_cert
        attribute = prepare_reginfo_private_key_possession_statement(
            signer_cert=signer_cert,
            include_cert=include_cert,
            modify_serial_number=modify_serial,
            modify_issuer=modify_issuer,
        )
        cert_req_msg["regInfo"].append(attribute)
        return cert_req_msg

    def test_success_with_embedded_cert(self):
        """
        GIVEN a valid statement with embedded cert.
        WHEN validating,
        THEN no exception is raised.
        """
        cert_req_msg = self._build_cert_req_msg(other_key=self.kem_key.public_key())
        cert_req_msg = self._add_reginfo_statement(cert_req_msg, include_cert=True)
        self.assertTrue(cert_req_msg["regInfo"].isValue)
        validate_private_key_pop_statement_cmrf(cert_req_msg, [self.signer_cert])  # Should not raise

    def test_rfc9883_bad_pop(self):
        """
        GIVEN a valid statement with embedded cert but an invalid signature.
        WHEN validating,
        THEN is BadPOP raised.
        """
        cert_req_msg = self._build_cert_req_msg(
            other_key=self.kem_key.public_key(),
            bad_pop=True,
        )
        cert_req_msg = self._add_reginfo_statement(cert_req_msg, include_cert=True)
        self.assertTrue(cert_req_msg["regInfo"].isValue)
        with self.assertRaises(BadPOP):
            validate_private_key_pop_statement_cmrf(cert_req_msg, [self.signer_cert])  # Should raise

    def test_signer_not_trusted(self):
        """GIVEN regInfo statement with embedded cert not in provided list WHEN validating THEN SignerNotTrusted raised."""
        cert_req_msg = self._build_cert_req_msg()
        cert_req_msg = self._add_reginfo_statement(cert_req_msg, include_cert=True)
        with self.assertRaises(SignerNotTrusted):
            validate_private_key_pop_statement_cmrf(cert_req_msg, [])  # empty cert list

    def test_bad_cert_id_modified_serial_number(self):
        """
        GIVEN statement without embedded cert and modified serial number.
        WHEN validating,
        THEN BadCertId raised.
        """
        cert_req_msg = self._build_cert_req_msg()
        # Include only issuerAndSerialNumber but modify serial to mismatch
        issuer_and_serial = prepare_issuer_and_serial_number(
            cert=self.signer_cert, modify_serial_number=True, modify_issuer=False
        )
        # Build attribute with modified serial and exclude cert
        attribute = prepare_reginfo_private_key_possession_statement(
            signer_cert=None,
            issuer_and_serial=issuer_and_serial,
            include_cert=False,
        )
        cert_req_msg["regInfo"].append(attribute)
        with self.assertRaises(BadCertId):
            validate_private_key_pop_statement_cmrf(cert_req_msg, [self.signer_cert])

    def test_bad_cert_template_subject_mismatch(self):
        """
        GIVEN certTemplate subject not matching signer cert.
        WHEN validating,
        THEN is BadCertTemplate raised.
        """
        cert_req_msg = self._build_cert_req_msg(subject=self.mismatch_subject_str)
        cert_req_msg = self._add_reginfo_statement(cert_req_msg, include_cert=True)
        with self.assertRaises(BadCertTemplate):
            validate_private_key_pop_statement_cmrf(cert_req_msg, [self.signer_cert], strict_subject_check=True)

    def test_bad_cert_template_missing_subject(self):
        """
        GIVEN certTemplate for a PrivateKeyPossessionStatement request, with a missing subject.
        WHEN validating,
        THEN is BadCertTemplate raised.
        """
        cert_req_msg = self._build_cert_req_msg(exclude_fields="subject,validity")
        cert_req_msg = self._add_reginfo_statement(cert_req_msg, include_cert=True)
        with self.assertRaises(BadCertTemplate):
            validate_private_key_pop_statement_cmrf(cert_req_msg, [self.signer_cert], strict_subject_check=True)

    def test_bad_cert_template_missing_public_key(self):
        """
        GIVEN certTemplate for a PrivateKeyPossessionStatement request, with a missing public key.
        WHEN validating,
        THEN is BadCertTemplate raised.
        """
        cert_req_msg = self._build_cert_req_msg(exclude_fields="publicKey,validity")
        cert_req_msg = self._add_reginfo_statement(cert_req_msg, include_cert=True)
        with self.assertRaises(BadCertTemplate):
            validate_private_key_pop_statement_cmrf(cert_req_msg, [self.signer_cert], strict_subject_check=True)

    def test_bad_cert_template_public_key_mismatch(self):
        """
        GIVEN certTemplate public key not matching signer cert.
        WHEN validating,
        THEN is BadCertTemplate raised.
        """
        poposk_input = cmputils.prepare_poposigningkeyinput(
            public_key=self.missmatch_kem_key.public_key() or self.signer_key.public_key(),
            sender=self.signer_subject_str,
        )
        cert_req_msg = self._build_cert_req_msg(
            other_key=self.kem_key.public_key(),
            poposk_input=poposk_input,
        )
        cert_req_msg = self._add_reginfo_statement(cert_req_msg, include_cert=True)
        with self.assertRaises(BadCertTemplate):
            validate_private_key_pop_statement_cmrf(cert_req_msg, [self.signer_cert])


if __name__ == "__main__":
    unittest.main()
