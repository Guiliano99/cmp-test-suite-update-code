import unittest

from pyasn1_alt_modules import rfc9480

from mock_ca.ca_handler import CAHandler

from pq_logic.keys.abstract_wrapper_keys import KEMPublicKey
from pq_logic.keys.sig_keys import MLDSAPrivateKey
from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import is_bit_set
from resources.certbuildutils import (
    build_csr,
    csr_add_attributes,
    prepare_private_key_possession_statement_attribute,
    sign_csr,
)
from resources.certutils import load_public_key_from_cert
from resources.cmputils import (
    build_ir_from_key,
    build_p10cr_from_csr,
    get_cert_from_pkimessage,
    get_pkistatusinfo,
)
from resources.keyutils import generate_key, load_private_key_from_file, prepare_subject_public_key_info
from resources.protectionutils import protect_pkimessage
from resources.utils import display_pki_status_info
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestMockCAIssuingCSRRFC9883(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock_ca_cert, cls.mock_ca_key = load_ca_cert_and_key()
        cls.kem_key = generate_key("ml-kem-512")  # type: ignore
        cls.kem_key: MLDSAPrivateKey
        cls.ca_handler = CAHandler(ca_cert=cls.mock_ca_cert, ca_key=cls.mock_ca_key)
        cls.sign_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.subject_str = "CN=Hans the Tester"
        cls._build_first_request_ir()

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
        _ = display_pki_status_info(response)
        cls.signer_cert = get_cert_from_pkimessage(response)

    @staticmethod
    def _pki_free_text_contains(status: rfc9480.PKIFreeText, substring: str) -> bool:
        """Check if any of the PKIStatusInfo's statusString entries contains the given substring."""
        if not status.isValue:
            return False

        for text in status:
            if substring in str(text):
                return True
        return False

    def _build_rfc9883_csr(self, kem_key: KEMPublicKey, bad_pop: bool = False) -> PKIMessageTMP:
        """Build an RFC 9883-compliant CRMF CSR (not p10cr) for a KEM public key.

        Returns a tuple of (protected_csr, kem_pub_key) where the CSR is PBMAC1-protected.
        """
        crs_attr = prepare_private_key_possession_statement_attribute(
            signer_cert=self.signer_cert,
            include_cert=True,
        )

        spki = prepare_subject_public_key_info(kem_key)
        csr = build_csr(signing_key=self.sign_key, common_name=self.subject_str, spki=spki, exclude_signature=True)
        csr = csr_add_attributes(csr, crs_attr)
        csr = sign_csr(csr=csr, signing_key=self.sign_key, bad_pop=bad_pop)
        p10cr = build_p10cr_from_csr(csr=csr, sender=self.subject_str, recipient="CN=Mock CA", for_mac=True)
        protected_ir = protect_pkimessage(p10cr, "pbmac1", password=b"SiemensIT")
        return protected_ir

    def test_issue_cert_rfc9883_csr_mac(self):
        """
        GIVEN a CSR using RFC 9883 PrivateKeyPossessionStatement for a KEM key and PBMAC1 protection,
        WHEN processed by the Mock CA,
        THEN the CA issues a certificate (IP, accepted) with the KEM public key.
        """
        protected_csr = self._build_rfc9883_csr(self.kem_key.public_key(), bad_pop=False)
        response = self.ca_handler.process_normal_request(protected_csr)
        status = get_pkistatusinfo(response)
        self.assertEqual(response["body"].getName(), "cp", response["body"].prettyPrint())
        self.assertEqual(status["status"].prettyPrint(), "accepted", status.prettyPrint())
        self.assertTrue(
            self._pki_free_text_contains(
                status["statusString"], "Processed RFC 9883 PrivateKeyPossessionStatement request."
            )
        )

        # Validate the issued certificate carries our KEM public key
        cert = get_cert_from_pkimessage(response)
        loaded_key = load_public_key_from_cert(cert)
        self.assertEqual(loaded_key, self.kem_key.public_key())

    def test_bad_pop_rfc9883_csr_mac(self):
        """
        GIVEN a CSR using RFC 9883 PrivateKeyPossessionStatement for a KEM key and PBMAC1 protection,
        WHEN processed by the Mock CA with a bad POP signature,
        THEN the CA rejects the request (REJ, badPOP).
        """
        other_key: KEMPublicKey = generate_key("ml-kem-512").public_key()
        protected_csr = self._build_rfc9883_csr(other_key, bad_pop=True)
        response = self.ca_handler.process_normal_request(protected_csr)
        status = get_pkistatusinfo(response)
        self.assertEqual(response["body"].getName(), "cp", response["body"].prettyPrint())
        self.assertEqual(status["status"].prettyPrint(), "rejection", status.prettyPrint())
        self.assertTrue(is_bit_set(status["failInfo"], "badPOP", exclusive=True), display_pki_status_info(status))


if __name__ == "__main__":
    unittest.main()
