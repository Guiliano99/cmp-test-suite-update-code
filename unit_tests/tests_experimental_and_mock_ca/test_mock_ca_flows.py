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

from resources.asn1utils import encode_to_der, get_set_bitstring_names
from resources.certbuildutils import prepare_cert_template, prepare_validity
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
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file

_SENDER = "CN=Mock CA Flow Tester"

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
    (BodyRelevantError, "badCertTemplate", 24, "ip", "ip", "cp", "rp", "error"),
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
    def _build_rr(key, cert):
        """Build a revocation request signed with the certificate to revoke."""
        rr = build_cmp_revoke_request(cert=cert, reason="keyCompromise")
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
        THEN every message is accepted, the CRL parses and OCSP answers successfully with `revoked`.
        """
        key, response, cert = self._issue_cert(implicit_confirm=False)

        response = self._post("/certConf", self._build_cert_conf(response, cert))
        self.assertEqual(response["body"].getName(), "pkiconf", response["body"].prettyPrint())

        self._assert_accepted(self._post("/rr", self._build_rr(key, cert)), "rp")

        # BUG-23: the CRL is empty, so only its availability is checked here.
        crl_response = self.client.get("/crl")
        self.assertEqual(crl_response.status_code, 200)
        self.assertEqual(crl_response.content_type, "application/pkix-crl")
        x509.load_der_x509_crl(crl_response.data)

        ocsp_request, _ = create_ocsp_request(cert, self.ca_handler.ca_cert)
        ocsp_response = self.client.post("/ocsp", data=ocsp_request.public_bytes(Encoding.DER))
        self.assertEqual(ocsp_response.status_code, 200)
        self.assertEqual(ocsp_response.content_type, "application/ocsp-response")
        parsed_ocsp = ocsp.load_der_ocsp_response(ocsp_response.data)
        self.assertEqual(parsed_ocsp.response_status, ocsp.OCSPResponseStatus.SUCCESSFUL)
        self.assertEqual(parsed_ocsp.certificate_status, ocsp.OCSPCertStatus.REVOKED)

    def test_p10cr(self):
        """
        GIVEN a MAC-protected p10cr.
        WHEN it is sent to the `/p10cr` route.
        THEN the response is an accepted cp.
        """
        self._assert_accepted(self._post("/p10cr", self._build_p10cr()), "cp")

    def test_ccr_with_compromised_key_is_rejected(self):
        """
        GIVEN a key registered as compromised and a ccr for that key, signed by a trusted CA.
        WHEN the ccr is sent to the `/issuing` route.
        THEN the response is an error with `badCertTemplate`, as for an ir with that key.

        This registers `data/keys/private-key-rsa.pem` as compromised on the class-level `CAHandler`, which every
        test of this class shares. No other test of this class uses that key.
        """
        bare_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        self.ca_handler.state.cert_state_db.add_compromised_key({"reason": "keyCompromise", "cert": bare_cert})
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

        response = self._post("/issuing", ccr)
        self.assertEqual(response["body"].getName(), "error", response["body"].prettyPrint())
        self.assertEqual(get_set_bitstring_names(get_pkistatusinfo(response)["failInfo"]), "badCertTemplate")

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
        for path in ["/issuing", "/ir", "/.well-known/cmp/p/ir", "/issuing/rr"]:
            with self.subTest(path=path):
                response = self.client.post(path, data=b"not a PKIMessage")
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.content_type, "application/pkixcmp")
                message = parse_pkimessage(response.data)
                self.assertEqual(message["body"].getName(), "error")
                self.assertEqual(get_set_bitstring_names(get_pkistatusinfo(message)["failInfo"]), "badDataFormat")

    def test_undecodable_body_without_error_handler(self):
        """
        GIVEN a body which is not a PKIMessage.
        WHEN it is sent to a route which does not catch the parse error.
        THEN the response is HTTP 500, which is today's behaviour (BUG-15: no Flask errorhandler).
        """
        self.assertEqual(self.client.post("/chameleon", data=b"not a PKIMessage").status_code, 500)

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
