import unittest

from pyasn1_alt_modules import rfc4211

from resources.ca_ra_utils import build_ip_cmp_message
from resources.certbuildutils import build_certificate, prepare_cert_template
from resources.certutils import load_public_key_from_cert
from resources.cmputils import (
    add_reg_info_to_pkimessage,
    build_ir_from_key,
    get_cert_from_pkimessage,
    get_pkistatusinfo,
    prepare_cert_req_msg,
    prepare_cert_request,
    prepare_poposigningkeyinput,
    prepare_reginfo_private_key_possession_statement,
    prepare_signature_popo,
)
from resources.exceptions import BadPOP
from resources.keyutils import generate_key
from resources.utils import display_pki_status_info
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestIssuingCertRFC9883(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cm = "CN=Hans the Tester"
        cls.signer_cert, cls.signer_key = build_certificate(common_name=cls.cm)
        cls.kem_key = generate_key("ml-kem-512")
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()

    def _build_cert_req_msg(self, other_key, subject_str: str, bad_pop: bool) -> rfc4211.CertReqMsg:
        """Build an RFC 9883-compliant CRMF IR (not p10cr) for a KEM public key.

        Returns a tuple of (protected_ir, kem_pub_key) where the IR is PBMAC1-protected.
        """
        cert_template = prepare_cert_template(
            key=other_key,
            subject=subject_str,
            include_cert_extensions=False,
        )

        cert_request = prepare_cert_request(
            key=self.kem_key.public_key(),
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
            signing_key=self.signer_key,
            cert_request=cert_request,
            poposk_input=poposk_input,
            sign_poposk_input=True,
            bad_pop=bad_pop,
        )

        # Assemble CertReqMsg with our explicit POPOSigningKey
        cert_req_msg = prepare_cert_req_msg(
            private_key=self.signer_key,
            cert_request=cert_request,
            popo_structure=popo,
        )

        # Build the IR PKIMessage with our CertReqMsg
        return cert_req_msg

    def _build_ir_fc9883_request(self, bad_pop: bool = False):
        """Build an RFC 9883-compliant CRMF IR (not p10cr) for a KEM public key.

        :param bad_pop: If True, build an IR with an invalid POP.
        :return: The PKIMessageTMP representing the IR request.
        """
        cert_req_msg = self._build_cert_req_msg(
            other_key=self.kem_key.public_key(),
            subject_str=self.cm,
            bad_pop=bad_pop,
        )

        ir = build_ir_from_key(
            signing_key=None,
            sender=self.cm,
            common_name=self.cm,
            recipient="CN=Mock CA",
            implicit_confirm=True,
            for_mac=True,
            cert_req_msg=cert_req_msg,
        )
        reginfo_attr = prepare_reginfo_private_key_possession_statement(
            signer_cert=self.signer_cert,
            include_cert=True,
        )
        ir = add_reg_info_to_pkimessage(ir, reginfo_attr, cert_req_index=0)
        return ir

    def test_correct_ir_rfc9883_request(self):
        """
        GIVEN an IR using RFC 9883 PrivateKeyPossessionStatement for a KEM key and PBMAC1 protection,
        WHEN processed by the Mock CA,
        THEN the CA issues a certificate (IP, accepted) with the KEM public key.
        """
        request = self._build_ir_fc9883_request(bad_pop=False)
        ip, certs = build_ip_cmp_message(
            request=request,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            signer_cert=self.signer_cert,
        )
        status = get_pkistatusinfo(ip)
        self.assertEqual(ip["body"].getName(), "ip", ip["body"].prettyPrint())
        self.assertEqual(status["status"].prettyPrint(), "accepted", display_pki_status_info(status))

        cert = get_cert_from_pkimessage(ip)
        loaded_key = load_public_key_from_cert(cert)
        self.assertEqual(loaded_key, self.kem_key.public_key())

    def test_bad_pop_ir_rfc9883_request(self):
        """
        GIVEN an IR using RFC 9883 PrivateKeyPossessionStatement for a KEM key and PBMAC1 protection,
        WHEN processed by the Mock CA with a bad POP signature,
        THEN the signature validation should fail.
        """
        request = self._build_ir_fc9883_request(bad_pop=True)
        with self.assertRaises(BadPOP) as cm:
            _ = build_ip_cmp_message(
                request=request,
                ca_cert=self.ca_cert,
                ca_key=self.ca_key,
                signer_cert=self.signer_cert,
            )

        self.assertIn("The PrivateKeyPossessionStatement request signature validation failed.", str(cm.exception))
