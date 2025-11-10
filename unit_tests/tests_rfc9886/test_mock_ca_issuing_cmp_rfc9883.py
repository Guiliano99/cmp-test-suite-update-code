import unittest

from mock_ca.ca_handler import CAHandler
from pyasn1_alt_modules import rfc4211, rfc9480

from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import is_bit_set
from resources.certbuildutils import (
    prepare_cert_template,
)
from resources.certutils import load_public_key_from_cert
from resources.cmputils import (
    add_reg_info_to_pkimessage,
    build_cr_from_key,
    build_ir_from_key,
    build_key_update_request,
    get_cert_from_pkimessage,
    get_pkistatusinfo,
    prepare_cert_req_msg,
    prepare_cert_request,
    prepare_poposigningkeyinput,
    prepare_reginfo_private_key_possession_statement,
    prepare_signature_popo,
)
from resources.keyutils import generate_key, load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import display_pki_status_info
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestMockCAIssuingCSRRFC9883(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock_ca_cert, cls.mock_ca_key = load_ca_cert_and_key()
        cls.kem_key_ir = generate_key("ml-kem-512")
        cls.ca_handler = CAHandler(ca_cert=cls.mock_ca_cert, ca_key=cls.mock_ca_key)
        cls.sign_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.subject_str = "CN=Hans the Tester"
        cls._build_first_request_ir()

        cls.kem_key_kur = generate_key("ml-kem-512")
        cls.kem_key_cr = generate_key("ml-kem-512")

        cls._ensure_unique_keys()

    @classmethod
    def _ensure_unique_keys(cls):
        """Ensure that all KEM keys are unique."""
        for x in range(100):
            if (
                cls.kem_key_ir.public_key() != cls.kem_key_cr.public_key()
                and cls.kem_key_ir.public_key() != cls.kem_key_kur.public_key()
                and cls.kem_key_cr.public_key() != cls.kem_key_kur.public_key()
            ):
                return

            if cls.kem_key_ir.public_key() != cls.kem_key_cr.public_key():
                cls.kem_key_cr = generate_key("ml-kem-512")
                continue

            if cls.kem_key_ir.public_key() != cls.kem_key_kur.public_key():
                cls.kem_key_kur = generate_key("ml-kem-512")
                continue

            if cls.kem_key_cr.public_key() != cls.kem_key_kur.public_key():
                cls.kem_key_kur = generate_key("ml-kem-512")
                continue

    @classmethod
    def _build_first_request_ir(cls) -> None:
        """Build an RFC 9883-compliant CRMF IR (not p10cr) for a KEM public key.

        Returns a tuple of (protected_ir, kem_pub_key) where the IR is PBMAC1-protected.
        """
        ir = build_ir_from_key(
            signing_key=cls.sign_key,
            sender=cls.subject_str,
            common_name=cls.subject_str,
            recipient="CN=Mock CA",
            implicit_confirm=True,
            for_mac=True,
        )
        protected_ir = protect_pkimessage(ir, "pbmac1", password=b"SiemensIT")
        response = cls.ca_handler.process_normal_request(protected_ir)
        status = get_pkistatusinfo(response)
        cls.signer_cert = get_cert_from_pkimessage(response)

    def _build_cert_req_msg(self, other_key, subject_str: str) -> rfc4211.CertReqMsg:
        """Build an RFC 9883-compliant CRMF IR (not p10cr) for a KEM public key.

        Returns a tuple of (protected_ir, kem_pub_key) where the IR is PBMAC1-protected.
        """
        # Prepare a certTemplate that carries the KEM public key
        cert_template = prepare_cert_template(
            key=other_key,
            subject=subject_str,
            include_cert_extensions=False,
        )

        # Build a bare CertRequest with that template (the signing key is the signer's key)
        cert_request = prepare_cert_request(
            key=other_key,
            cert_template=cert_template,
            cert_req_id=0,
        )

        # POPOSigningKeyInput: must include sender (directoryName) and publicKey matching certTemplate
        poposk_input = prepare_poposigningkeyinput(
            public_key=other_key,
            sender=subject_str,
        )

        # Prepare POPOSigningKey that signs only the poposkInput per RFC 9883 Section 5
        popo = prepare_signature_popo(
            signing_key=self.sign_key,
            cert_request=cert_request,
            poposk_input=poposk_input,
            sign_poposk_input=True,
        )

        # Assemble CertReqMsg with our explicit POPOSigningKey
        cert_req_msg = prepare_cert_req_msg(
            private_key=self.mock_ca_key,
            cert_request=cert_request,
            popo_structure=popo,
        )

        # Build the IR PKIMessage with our CertReqMsg
        return cert_req_msg

    def _build_rfc9883_ir(self):
        cert_req_msg = self._build_cert_req_msg(other_key=self.kem_key_ir.public_key(), subject_str=self.subject_str)
        ir = build_ir_from_key(
            signing_key=None,
            sender=self.subject_str,
            recipient="CN=Mock CA",
            cert_req_msg=cert_req_msg,
            implicit_confirm=False,
            for_mac=True,
        )
        # Attach regInfo PrivateKeyPossessionStatement with embedded signer cert
        reginfo_attr = prepare_reginfo_private_key_possession_statement(
            signer_cert=self.signer_cert,
            include_cert=True,
        )
        ir = add_reg_info_to_pkimessage(ir, reginfo_attr, cert_req_index=0)

        # Protect with PBMAC1 (MAC) to avoid signer chain requirements
        protected_ir = protect_pkimessage(ir, "pbmac1", password=b"SiemensIT")
        return protected_ir

    def _build_rfc9883_cr(self) -> PKIMessageTMP:
        cert_req_msg = self._build_cert_req_msg(other_key=self.kem_key_cr.public_key(), subject_str=self.subject_str)
        cr = build_cr_from_key(
            signing_key=None,
            cert_req_msg=cert_req_msg,
            sender=self.subject_str,
            recipient="CN=Mock CA",
            for_mac=True,
        )
        # Attach regInfo PrivateKeyPossessionStatement with embedded signer cert
        reginfo_attr = prepare_reginfo_private_key_possession_statement(
            signer_cert=self.signer_cert,
            include_cert=True,
        )
        cr = add_reg_info_to_pkimessage(cr, reginfo_attr, cert_req_index=0)

        # Protect with PBMAC1 (MAC) to avoid signer chain requirements
        protected_cr = protect_pkimessage(cr, "pbmac1", password=b"SiemensIT")
        return protected_cr

    def _build_rfc9883_kur(self) -> PKIMessageTMP:
        cert_req_msg = self._build_cert_req_msg(other_key=self.kem_key_kur.public_key(), subject_str=self.subject_str)
        kur = build_key_update_request(
            signing_key=None,
            sender=self.subject_str,
            recipient="CN=Mock CA",
            cert_req_msg=cert_req_msg,
            implicit_confirm=False,
            for_mac=False,
        )
        # Attach regInfo PrivateKeyPossessionStatement with embedded signer cert
        reginfo_attr = prepare_reginfo_private_key_possession_statement(
            signer_cert=self.signer_cert,
            include_cert=True,
        )
        kur = add_reg_info_to_pkimessage(kur, reginfo_attr, cert_req_index=0)

        # Protect with PBMAC1 (MAC) to avoid signer chain requirements

        protected_kur = protect_pkimessage(
            kur, "signature", private_key=self.sign_key, cert_chain=[self.signer_cert, self.mock_ca_cert]
        )
        return protected_kur

    def test_issue_cert_rfc9883_ir_mac(self):
        """
        GIVEN an IR using RFC 9883 PrivateKeyPossessionStatement for a KEM key and PBMAC1 protection,
        WHEN processed by the Mock CA,
        THEN the CA issues a certificate (IP, accepted) with the KEM public key.
        """
        protected_ir = self._build_rfc9883_ir()
        response = self.ca_handler.process_normal_request(protected_ir)
        status = get_pkistatusinfo(response)
        self.assertEqual(response["body"].getName(), "ip", response["body"].prettyPrint())
        self.assertEqual(status["status"].prettyPrint(), "accepted", display_pki_status_info(status))

        # Validate the issued certificate carries our KEM public key
        cert = get_cert_from_pkimessage(response)
        loaded_key = load_public_key_from_cert(cert)
        self.assertEqual(loaded_key, self.kem_key_ir.public_key())

    def test_issue_cert_rfc9883_cr_mac(self):
        """
        GIVEN a CR using RFC 9883 PrivateKeyPossessionStatement for a KEM key and PBMAC1 protection,
        WHEN processed by the Mock CA,
        THEN the CA issues a certificate (CP, accepted) with the KEM public key.
        """
        protected_ir = self._build_rfc9883_cr()
        response = self.ca_handler.process_normal_request(protected_ir)
        status = get_pkistatusinfo(response)
        self.assertEqual(response["body"].getName(), "cp", response["body"].prettyPrint())
        self.assertEqual(status["status"].prettyPrint(), "accepted", display_pki_status_info(status))

        # Validate the issued certificate carries our KEM public key
        cert = get_cert_from_pkimessage(response)
        loaded_key = load_public_key_from_cert(cert)
        self.assertEqual(loaded_key, self.kem_key_cr.public_key())

    @staticmethod
    def _pki_free_text_contains(status: rfc9480.PKIFreeText, substring: str) -> bool:
        """Check if any of the PKIStatusInfo's statusString entries contains the given substring."""
        if not status.isValue:
            return False

        for text in status:
            if substring in str(text):
                return True
        return False

    def test_issue_cert_rfc9883_kur(self):
        """
        GIVEN a KUR using RFC 9883 PrivateKeyPossessionStatement for a KEM key,
        WHEN processed by the Mock CA,
        THEN the CA rejects the request (rejection) with appropriate status info.
        """
        protected_ir = self._build_rfc9883_kur()
        response = self.ca_handler.process_normal_request(protected_ir)
        status = get_pkistatusinfo(response)
        self.assertEqual(response["body"].getName(), "kup", response["body"].prettyPrint())
        self.assertEqual(status["status"].prettyPrint(), "rejection", status.prettyPrint())

        self.assertTrue(
            self._pki_free_text_contains(
                status["statusString"], "Private key possession statement is not allowed in KUR messages."
            ),
            display_pki_status_info(status),
        )
        self.assertTrue(
            is_bit_set(status["failInfo"], "badRequest, badPOP", exclusive=False), display_pki_status_info(status)
        )


if __name__ == "__main__":
    unittest.main()
