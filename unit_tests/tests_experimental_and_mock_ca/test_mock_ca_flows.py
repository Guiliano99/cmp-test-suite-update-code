# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import base64
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from mock_ca import rev_handler
from mock_ca.ca_handler import CAHandler, create_app
from mock_ca.client import build_example_rsa_mac_request
from mock_ca.operation_dbs import load_kari_certs
from pyasn1_alt_modules import rfc9480

from resources.asn1utils import encode_to_der, get_set_bitstring_names
from resources.certbuildutils import build_certificate, prepare_cert_template, prepare_validity
from resources.certutils import build_cert_chain_from_dir, create_ocsp_request, parse_certificate
from resources.cmputils import (
    build_ccr_from_key,
    build_cert_conf_from_resp,
    build_cmp_revoke_request,
    build_ir_from_key,
    build_p10cr_from_key,
    display_pki_status_info,
    get_cert_from_pkimessage,
    get_pkistatusinfo,
    parse_pkimessage,
)
from resources.exceptions import (
    BadKeyUsage,
    BadMessageCheck,
    BadRequest,
    BadSigAlgID,
    BodyRelevantError,
    CMPTestSuiteError,
)
from resources.keyutils import generate_key, load_private_key_from_file
from resources.prepare_alg_ids import prepare_sig_alg_id
from resources.protectionutils import protect_pkimessage, verify_pkimessage_protection
from resources.utils import load_and_decode_pem_file

_SENDER = "CN=Mock CA Flow Tester"
_OTHER_SUBJECT = "CN=Mock CA Flow Tester 2"

# Today's behaviour, right or wrong. Columns: the exception, the failinfo the client gets (set by name, not by
# `bit_num`), the `bit_num` the class declares, then the response body when a call inside the stage raises it, for
# the stages protection, issuing, p10cr, rr and certConf. A (body, failinfo) cell overrides the row's failinfo.
# The patched calls sit inside each stage's own except chain, so an exception the stage does not catch reaches the
# generic chain of the request handler, as a real failure would.
_ERROR_TABLE = [
    # BUG-15: systemFailure is bit 25, bit 26 is duplicateCertReq. The client gets bit 25.
    (CMPTestSuiteError, "systemFailure", 26, "error", "ip", "cp", "rp", "error"),
    (BadRequest, "badRequest", 2, "error", "ip", "cp", "rp", "error"),
    (BadMessageCheck, "badMessageCheck", 1, "error", "ip", "cp", "rp", "error"),
    (BadKeyUsage, "notAuthorized", 23, "error", "ip", "cp", "rp", "error"),
    # BUG-15: badDataFormat is bit 5. The client gets bit 5.
    (BadSigAlgID, "badDataFormat", 0, "error", "ip", "cp", "rp", "error"),
    # BUG-15: inherits bit 26 from the keyutils_py base (systemFailure is 25); every instance sets its failinfo.
    (BodyRelevantError, "badCertTemplate", 26, "ip", "ip", "cp", "rp", "error"),
    (InvalidSignature, "badMessageCheck", None, "error", "error", "error", "rp", "error"),
    # The revocation handler reports every ValueError as badMessageCheck.
    (ValueError, "systemFailure", None, "error", "error", "error", ("rp", "badMessageCheck"), "error"),
]


def _mac_protect(pki_message):
    """Protect a PKIMessage with the pre-shared secret of the Mock CA."""
    return protect_pkimessage(pki_message, "password_based_mac", password="SiemensIT")


class TestMockCAFlows(unittest.TestCase):
    """Test the CA flows over the Flask routes, in-process and without opening a port."""

    @classmethod
    def setUpClass(cls):
        cls.ca_handler = CAHandler()
        cls.client = create_app(cls.ca_handler).test_client()

    def _post(self, path: str, pki_message):
        """Send a PKIMessage to a route which must answer with HTTP 200 and return the parsed response."""
        response = self.client.post(path, data=encode_to_der(pki_message))
        self.assertEqual(response.status_code, 200, response.data)
        return parse_pkimessage(response.data)

    def _assert_accepted(self, response, body_name: str) -> None:
        """Assert the body name of a response and that its status is `accepted`."""
        self.assertEqual(response["body"].getName(), body_name, response["body"].prettyPrint())
        self.assertEqual(str(get_pkistatusinfo(response)["status"]), "accepted", display_pki_status_info(response))

    def _assert_rejected(self, response, body_name: str, failinfo: str) -> None:
        """Assert the body name of a response, that its status is `rejection` and its exact failinfo."""
        status_info = get_pkistatusinfo(response)
        self.assertEqual(response["body"].getName(), body_name, response["body"].prettyPrint())
        self.assertEqual(str(status_info["status"]), "rejection", display_pki_status_info(response))
        self.assertEqual(get_set_bitstring_names(status_info["failInfo"]), failinfo)

    def _get_crl(self) -> x509.CertificateRevocationList:
        """Fetch and parse the CRL from the `/crl` route."""
        crl_response = self.client.get("/crl")
        self.assertEqual(crl_response.status_code, 200)
        self.assertEqual(crl_response.content_type, "application/pkix-crl")
        return x509.load_der_x509_crl(crl_response.data)

    def _issue_cert(self, implicit_confirm: bool = True):
        """Issue a certificate over the `/issuing` route and return the key, the response and the certificate."""
        key = generate_key("ecc")
        ir = build_ir_from_key(
            key, common_name=_SENDER, sender=_SENDER, implicit_confirm=implicit_confirm, for_mac=True
        )
        response = self._post("/issuing", _mac_protect(ir))
        self._assert_accepted(response, "ip")
        return key, response, get_cert_from_pkimessage(response)

    @staticmethod
    def _build_cert_conf(response, cert, pvno: int = 3, hash_alg: str | None = "sha256"):
        """Build a protected certConf for an issued certificate."""
        cert_conf = build_cert_conf_from_resp(
            ca_message=response,
            cert=cert,
            pvno=pvno,
            sender_nonce=os.urandom(16),
            sender=_SENDER,
            recipient="CN=Mock CA",
            for_mac=True,
            exclude_fields=None,
            hash_alg=hash_alg,
        )
        return _mac_protect(cert_conf)

    @staticmethod
    def _build_rr(key, cert, reason: str = "keyCompromise"):
        """Build a revocation request signed with the certificate to revoke."""
        rr = build_cmp_revoke_request(cert=cert, reason=reason)
        return protect_pkimessage(rr, "signature", private_key=key, cert=cert, certs_dir="data/unittest/")

    @staticmethod
    def _build_p10cr():
        """Build a protected p10cr for a new key."""
        p10cr = build_p10cr_from_key(
            generate_key("ecc"), common_name=_SENDER, sender=_SENDER, implicit_confirm=True, for_mac=True
        )
        return _mac_protect(p10cr)

    def test_ir_cert_conf_rr_then_crl_and_ocsp(self):
        """
        GIVEN a certificate issued with an ir and confirmed with a certConf.
        WHEN it is revoked with an rr and the CRL and OCSP routes are asked afterwards.
        THEN every message is accepted, the CRL lists the serial number and OCSP answers successfully with
        `revoked`, both with the stored revocation date and the reason `keyCompromise`, and the CRL carries no
        issuing distribution point.
        """
        key, response, cert = self._issue_cert(implicit_confirm=False)

        response = self._post("/certConf", self._build_cert_conf(response, cert))
        self.assertEqual(response["body"].getName(), "pkiconf", response["body"].prettyPrint())

        self._assert_accepted(self._post("/rr", self._build_rr(key, cert)), "rp")
        # CRLs and OCSP responses carry whole seconds.
        revoked_date = self.ca_handler.state.certificate_db.get_cert(cert).revoked_entry.revoked_date
        revoked_date = revoked_date.replace(microsecond=0)

        serial_number = int(cert["tbsCertificate"]["serialNumber"])
        crl = self._get_crl()
        with self.assertRaises(x509.ExtensionNotFound):
            crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint)
        crl_entry = crl.get_revoked_certificate_by_serial_number(serial_number)
        self.assertIsNotNone(crl_entry)
        self.assertEqual(crl_entry.revocation_date_utc, revoked_date)
        crl_reason = crl_entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
        self.assertEqual(crl_reason, x509.ReasonFlags.key_compromise)

        ocsp_request, _ = create_ocsp_request(cert, self.ca_handler.ca_cert)
        ocsp_response = self.client.post("/ocsp", data=ocsp_request.public_bytes(Encoding.DER))
        self.assertEqual(ocsp_response.status_code, 200)
        self.assertEqual(ocsp_response.content_type, "application/ocsp-response")
        parsed_ocsp = ocsp.load_der_ocsp_response(ocsp_response.data)
        self.assertEqual(parsed_ocsp.response_status, ocsp.OCSPResponseStatus.SUCCESSFUL)
        self.assertEqual(parsed_ocsp.certificate_status, ocsp.OCSPCertStatus.REVOKED)
        self.assertEqual(parsed_ocsp.revocation_time_utc, revoked_date)
        self.assertEqual(parsed_ocsp.revocation_reason, x509.ReasonFlags.key_compromise)

    def test_revived_cert_leaves_the_crl(self):
        """
        GIVEN a certificate revoked with an rr.
        WHEN it is revived with an rr for `removeFromCRL`.
        THEN the CRL lists it after the revocation and no longer after the revival, and OCSP answers `good`.
        """
        key, _, cert = self._issue_cert()
        serial_number = int(cert["tbsCertificate"]["serialNumber"])

        self._assert_accepted(self._post("/rr", self._build_rr(key, cert)), "rp")
        self.assertIsNotNone(self._get_crl().get_revoked_certificate_by_serial_number(serial_number))

        self._assert_accepted(self._post("/rr", self._build_rr(key, cert, reason="removeFromCRL")), "rp")
        self.assertIsNone(self._get_crl().get_revoked_certificate_by_serial_number(serial_number))

        ocsp_request, _ = create_ocsp_request(cert, self.ca_handler.ca_cert)
        ocsp_response = self.client.post("/ocsp", data=ocsp_request.public_bytes(Encoding.DER))
        self.assertEqual(ocsp_response.status_code, 200)
        self.assertEqual(ocsp.load_der_ocsp_response(ocsp_response.data).certificate_status, ocsp.OCSPCertStatus.GOOD)

    def test_crl_route_and_genp_share_the_crl_number(self):
        """
        GIVEN the Mock CA.
        WHEN a CRL is fetched from `/crl`, then from the source of the genp currentCRL
        (`RevocationHandler.get_current_crl`), then from `/crl` again.
        THEN each CRL number is one more than the one before (RFC 5280 Section 5.2.3).
        """

        def crl_number(crl: x509.CertificateRevocationList) -> int:
            return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number

        first = crl_number(self._get_crl())
        genp_crl = self.ca_handler.rev_handler.get_current_crl(self.ca_handler.ca_key, self.ca_handler.ca_cert)
        genp = crl_number(x509.load_der_x509_crl(genp_crl))
        last = crl_number(self._get_crl())
        self.assertEqual([genp, last], [first + 1, first + 2])

    def test_compromised_key_is_rejected_for_another_subject(self):
        """
        GIVEN a key whose certificate was revoked with an rr for `keyCompromise`.
        WHEN an ir for the same public key and another subject is sent to `/issuing`.
        THEN the response is an ip with status `rejection` and `badCertTemplate`.
        """
        key, _, cert = self._issue_cert()
        self._assert_accepted(self._post("/rr", self._build_rr(key, cert)), "rp")

        ir = build_ir_from_key(key, common_name=_OTHER_SUBJECT, sender=_SENDER, implicit_confirm=True, for_mac=True)
        self._assert_rejected(self._post("/issuing", _mac_protect(ir)), "ip", "badCertTemplate")

    def test_cert_req_handler_rejects_p10cr_with_compromised_key(self):
        """
        GIVEN a key whose certificate was revoked with an rr for `keyCompromise`.
        WHEN a p10cr for that key and another subject goes straight to the certificate request handler, as the
        nested handler sends its inner requests.
        THEN the response is a cp with status `rejection` and `badCertTemplate`.
        """
        key, _, cert = self._issue_cert()
        self._assert_accepted(self._post("/rr", self._build_rr(key, cert)), "rp")

        p10cr = build_p10cr_from_key(
            key, common_name=_OTHER_SUBJECT, sender=_SENDER, implicit_confirm=True, for_mac=True
        )
        response = self.ca_handler.cert_req_handler.process_cert_request(_mac_protect(p10cr))
        self._assert_rejected(response, "cp", "badCertTemplate")

    def test_rr_with_dh_based_mac(self):
        """
        GIVEN a confirmed X25519, X448 or ECDH P-256 certificate issued by the Mock CA.
        WHEN an rr protected with DHBasedMac against the matching CA key-agreement certificate is sent to `/rr`,
        with a valid or a modified protection value, or from a P-256 certificate without `keyAgreement` key usage.
        THEN the valid rr is accepted with a DHBasedMac-protected rp the client can verify and the certificate is
        revoked. The modified rr is rejected with `badMessageCheck`, the rr of the `digitalSignature`-only
        certificate with `notAuthorized`, and both certificates stay valid (RFC 9810 Section 5.1.3.2).
        """
        kari_certs = load_kari_certs()
        p256 = {"curve": "secp256r1"}
        # Columns: key name, key arguments, key usage, modify the protection value, expected failinfo.
        cases = [
            ("x25519", {}, "keyAgreement", False, None),
            ("x25519", {}, "keyAgreement", True, "badMessageCheck"),
            ("x448", {}, "keyAgreement", False, None),
            ("x448", {}, "keyAgreement", True, "badMessageCheck"),
            ("ecc", p256, "keyAgreement", False, None),
            ("ecc", p256, "keyAgreement", True, "badMessageCheck"),
            ("ecc", p256, "digitalSignature", False, "notAuthorized"),
        ]
        for name, key_args, key_usage, bad_message_check, failinfo in cases:
            with self.subTest(key=name, key_usage=key_usage, bad_message_check=bad_message_check):
                key = generate_key(name, **key_args)
                cert, _ = build_certificate(
                    private_key=key,
                    common_name=_SENDER,
                    key_usage=key_usage,
                    include_ski=True,
                    ca_cert=self.ca_handler.ca_cert,
                    ca_key=self.ca_handler.ca_key,
                )
                self.ca_handler.state.add_certs([cert])
                rr = protect_pkimessage(
                    build_cmp_revoke_request(cert=cert, reason="keyCompromise"),
                    "dh",
                    private_key=key,
                    cert=cert,
                    peer=kari_certs[f"{name}_cert"],
                    bad_message_check=bad_message_check,
                )

                response = self._post("/rr", rr)
                if failinfo is None:
                    self._assert_accepted(response, "rp")
                    self.assertEqual(response["header"]["protectionAlg"]["algorithm"], rfc9480.id_DHBasedMac)
                    verify_pkimessage_protection(response, private_key=key)
                    self.assertTrue(self.ca_handler.rev_handler.is_revoked(cert))
                else:
                    status_info = get_pkistatusinfo(response)
                    self.assertEqual(response["body"].getName(), "rp", response["body"].prettyPrint())
                    self.assertEqual(str(status_info["status"]), "rejection", display_pki_status_info(response))
                    self.assertEqual(get_set_bitstring_names(status_info["failInfo"]), failinfo)
                    self.assertFalse(self.ca_handler.rev_handler.is_revoked(cert))

    def test_p10cr(self):
        """
        GIVEN a MAC-protected p10cr.
        WHEN it is sent to the `/p10cr` route.
        THEN the response is an accepted cp.
        """
        self._assert_accepted(self._post("/p10cr", self._build_p10cr()), "cp")

    def test_ccr_with_compromised_key_is_rejected(self):
        """
        GIVEN a revoked certificate and a ccr for its key, signed by a trusted CA.
        WHEN the ccr is sent to the `/issuing` route.
        THEN the response is a ccp with status `rejection` and `badCertTemplate`, as for an ir with that key.

        This revokes the certificate of `data/keys/private-key-rsa.pem` on the class-level `CAHandler`, which every
        test of this class shares. No other test of this class uses that key.
        """
        bare_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        self.ca_handler.state.add_certs([bare_cert])
        self.ca_handler.rev_handler.mark_as_revoked(bare_cert, reason="keyCompromise")
        key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        now = datetime.now(timezone.utc)
        cert_template = prepare_cert_template(
            key,
            validity=prepare_validity(now - timedelta(days=1), now + timedelta(days=100)),
            subject=_SENDER,
            issuer="CN=Mock CA",
            version="v3",
            sign_alg=prepare_sig_alg_id(key, hash_alg="sha256"),
            include_fields="subject,issuer,validity,publicKey,version,signingAlg",
        )
        ccr = build_ccr_from_key(key, cert_template=cert_template, recipient="CN=Mock CA")
        trusted_ca_cert = parse_certificate(load_and_decode_pem_file("data/trusted_ras/ra_cms_cert_ecdsa.pem"))
        ccr = protect_pkimessage(
            ccr,
            "signature",
            private_key=load_private_key_from_file("data/keys/private-key-ecdsa.pem", password="11111"),
            cert_chain=build_cert_chain_from_dir(trusted_ca_cert, "data/unittest"),
        )

        self._assert_rejected(self._post("/issuing", ccr), "ccp", "badCertTemplate")

    def test_cert_conf_with_pvno_1_is_unsupported_version(self):
        """
        GIVEN an issued certificate and a certConf with pvno 1 (cmp1999) and without hashAlg.
        WHEN the certConf is sent to the `/certConf` route.
        THEN the response is an error with exactly `unsupportedVersion` and pvno 2, the lowest supported version
        (RFC 9483 Section 3.5, RFC 9810 Section 7).
        """
        _, response, cert = self._issue_cert(implicit_confirm=False)
        result = self._post("/certConf", self._build_cert_conf(response, cert, pvno=1, hash_alg=None))
        self.assertEqual(result["body"].getName(), "error", result["body"].prettyPrint())
        self.assertEqual(get_set_bitstring_names(get_pkistatusinfo(result)["failInfo"]), "unsupportedVersion")
        self.assertEqual(int(result["header"]["pvno"]), 2)

    def test_read_routes(self):
        """
        GIVEN a certificate issued over the well-known route.
        WHEN the read-only routes are asked.
        THEN they return the issued certificate, the root certificate and the Sun-Hybrid data.
        """
        ir, _ = build_example_rsa_mac_request(_SENDER)
        response = self._post("/.well-known/cmp/p/ir", ir)
        self._assert_accepted(response, "ip")
        serial_number = int(get_cert_from_pkimessage(response)["tbsCertificate"]["serialNumber"])

        cert_response = self.client.get(f"/cert/{serial_number}")
        self.assertEqual(cert_response.status_code, 200)
        self.assertEqual(int(parse_certificate(cert_response.data)["tbsCertificate"]["serialNumber"]), serial_number)

        root_response = self.client.get("/root-cert")
        self.assertEqual(root_response.status_code, 200)
        self.assertEqual(base64.b64decode(root_response.data), encode_to_der(self.ca_handler.ca_cert))

        for path in ["/pubkey/1", "/sig/1"]:
            with self.subTest(path=path):
                sun_hybrid_response = self.client.get(path)
                self.assertEqual(sun_hybrid_response.status_code, 200)
                self.assertTrue(sun_hybrid_response.data)

    def test_undecodable_body_is_rejected(self):
        """
        GIVEN a body which is not a PKIMessage.
        WHEN it is sent to a CMP route.
        THEN the response is HTTP 400 with an error message and `badDataFormat`.
        """
        paths = ["/issuing", "/ir", "/.well-known/cmp/p/ir", "/issuing/rr"]
        paths += ["/chameleon", "/sun-hybrid", "/multi-auth", "/cert-discovery", "/related-cert"]
        paths += ["/catalyst-sig", "/catalyst-issuing"]
        for path in paths:
            with self.subTest(path=path):
                response = self.client.post(path, data=b"not a PKIMessage")
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.content_type, "application/pkixcmp")
                message = parse_pkimessage(response.data)
                self.assertEqual(message["body"].getName(), "error")
                self.assertEqual(get_set_bitstring_names(get_pkistatusinfo(message)["failInfo"]), "badDataFormat")

    def test_body_not_allowed_on_route(self):
        """
        GIVEN a valid p10cr.
        WHEN it is sent to the `/ir` route, which only allows ir and cr.
        THEN the response is HTTP 400 with an error message and `badRequest`.
        """
        response = self.client.post("/ir", data=encode_to_der(self._build_p10cr()))
        self.assertEqual(response.status_code, 400)
        message = parse_pkimessage(response.data)
        self.assertEqual(message["body"].getName(), "error")
        self.assertEqual(get_set_bitstring_names(get_pkistatusinfo(message)["failInfo"]), "badRequest")

    def test_exception_to_cmp_response_table(self):
        """
        GIVEN an exception raised by a lower layer in a stage of the main request path.
        WHEN the request is processed.
        THEN the response has the rejection, the body and the failinfo recorded in `_ERROR_TABLE`.
        """
        key, response, cert = self._issue_cert()
        ir = _mac_protect(build_ir_from_key(generate_key("ecc"), common_name=_SENDER, sender=_SENDER, for_mac=True))
        stages = {
            "protection": (self.ca_handler, "verify_protection", "/ir", ir),
            "issuing": (self.ca_handler.cert_req_handler, "process_ir", "/ir", ir),
            "p10cr": (self.ca_handler.cert_req_handler, "process_p10cr", "/p10cr", self._build_p10cr()),
            "rr": (rev_handler, "validate_rr_crl_entry_details_reason", "/rr", self._build_rr(key, cert)),
            "certConf": (self.ca_handler, "process_cert_conf", "/certConf", self._build_cert_conf(response, cert)),
        }

        for exception_class, row_failinfo, bit_num, *cells in _ERROR_TABLE:
            self.assertEqual(getattr(exception_class, "bit_num", None), bit_num, exception_class)
            for (stage, (target, method, path, request)), cell in zip(stages.items(), cells, strict=True):
                body_name, failinfo = cell if isinstance(cell, tuple) else (cell, row_failinfo)
                with self.subTest(stage=stage, exception=exception_class.__name__):
                    if exception_class is BodyRelevantError:
                        exception = BodyRelevantError("Lower layer", failinfo=failinfo, pki_message=request)
                    else:
                        exception = exception_class("Lower layer")

                    with patch.object(target, method, side_effect=exception):
                        result = self._post(path, request)

                    status_info = get_pkistatusinfo(result)
                    self.assertEqual(result["body"].getName(), body_name)
                    self.assertEqual(str(status_info["status"]), "rejection")
                    self.assertEqual(get_set_bitstring_names(status_info["failInfo"]), failinfo)


if __name__ == "__main__":
    unittest.main()
