# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""The Mock CA rejects every pvno other than cmp2000(2) and cmp2021(3) with `unsupportedVersion`.

RFC 9483 Section 3.5: "The pvno MUST be cmp2000(2) or cmp2021(3). (failInfo bit: unsupportedVersion)".
"""

import os
import unittest
from unittest import mock

from mock_ca import ca_handler
from mock_ca.ca_handler import CAHandler
from pq_logic.hybrid_sig.chameleon_logic import build_paired_csr

from resources.asn1utils import is_bit_set
from resources.certutils import parse_certificate
from resources.cmputils import (
    build_cert_conf_from_resp,
    build_cmp_revoke_request,
    build_ir_from_key,
    build_nested_pkimessage,
    build_p10cr_from_csr,
    build_p10cr_from_key,
    generate_unique_byte_values,
    get_cert_from_pkimessage,
    get_cmp_message_type,
    get_pkistatusinfo,
    parse_pkimessage,
    prepare_popo_challenge_for_non_signing_key,
)
from resources.general_msg_utils import build_cmp_general_message
from resources.keyutils import generate_key, load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import display_pki_status_info, load_and_decode_pem_file
from unit_tests.utils_for_test import de_and_encode_pkimessage, load_ca_cert_and_key, try_encode_pyasn1

_PASSWORD = "SiemensIT"
_SENDER = "CN=Hans the Tester"
_UNSUPPORTED_PVNOS = (-1, 0, 1, 4)
_SUPPORTED_PVNOS = (2, 3)
# The routes of the hybrid views, which have their own `certConf` handling.
_CERT_CONF_ROUTES = ("/sun-hybrid", "/cert-discovery", "/related-cert", "/catalyst-sig", "/catalyst-issuing")
_ALL_ROUTES = ("/chameleon", "/multi-auth", *_CERT_CONF_ROUTES)


def _mac_protect(pki_message):
    """Protect a request and encode/decode it, as if it was received over the wire."""
    return de_and_encode_pkimessage(protect_pkimessage(pki_message, "pbmac1", password=_PASSWORD))


def _build_ir(pvno: int, implicit_confirm: bool = True):
    return _mac_protect(
        build_ir_from_key(
            generate_key("ecc"),
            common_name=_SENDER,
            sender=_SENDER,
            implicit_confirm=implicit_confirm,
            for_mac=True,
            pvno=pvno,
        )
    )


def _build_ir_with_challenge_popo(key, use_key_enc: bool, pvno: int):
    """Build an ir for a non-signing key, which asks the CA for a challenge (`popdecc`)."""
    popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=use_key_enc)
    return _mac_protect(build_ir_from_key(key, popo=popo, common_name=_SENDER, sender=_SENDER, for_mac=True, pvno=pvno))


def _build_p10cr(pvno: int, implicit_confirm: bool = True):
    return _mac_protect(
        build_p10cr_from_key(
            generate_key("ecc"), sender=_SENDER, common_name=_SENDER, implicit_confirm=implicit_confirm, pvno=pvno
        )
    )


def _build_paired_p10cr(pvno: int):
    csr = build_paired_csr(
        base_private_key=load_private_key_from_file("./data/keys/private-key-ecdsa.pem"),
        delta_private_key=load_private_key_from_file("./data/keys/private-key-ml-dsa-44-seed.pem"),
    )
    return _mac_protect(build_p10cr_from_csr(csr, sender=_SENDER, implicit_confirm=True, pvno=pvno))


def _build_cert_conf(response, pvno: int):
    """Build a `certConf` for the certificate of the response, with the given pvno."""
    cert_conf = build_cert_conf_from_resp(
        ca_message=response,
        cert=get_cert_from_pkimessage(response),
        pvno=pvno,
        sender_nonce=os.urandom(16),
        sender=_SENDER,
        recipient="CN=Mock CA",
        for_mac=True,
        exclude_fields=None,
    )
    return _mac_protect(cert_conf)


def _ra_protect(nested, wire: bool = True):
    """Protect a nested message with the trusted RA.

    :param wire: Whether to encode and decode it, as if it was received over the wire. `parse_pkimessage` decodes
    only one level of `nested`, so a batch of added-protection requests is passed as it was built.
    """
    ra_key = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")
    ra_cert = parse_certificate(load_and_decode_pem_file("./data/trusted_ras/ra_cms_cert_ecdsa.pem"))
    nested = protect_pkimessage(nested, protection="signature", cert=ra_cert, private_key=ra_key)
    if not wire:
        return nested
    return parse_pkimessage(try_encode_pyasn1(nested, exclude_pretty_print=True))


def _added_protection(inner, pvno: int = 2, wire: bool = True):
    """Wrap a message as an added protection request with the given outer pvno."""
    nested = build_nested_pkimessage(other_messages=inner, for_added_protection=True, pvno=pvno)
    return _ra_protect(nested, wire=wire)


def _batch(messages, pvno: int = 2, wire: bool = True):
    """Wrap messages as a batch, with unique transactionID and senderNonce."""
    tx_id, sender_nonce = generate_unique_byte_values(length=2, size=16)
    nested = build_nested_pkimessage(
        other_messages=messages, transaction_id=tx_id, sender_nonce=sender_nonce, pvno=pvno
    )
    return _ra_protect(nested, wire=wire)


def _build_ir_unique(pvno: int, implicit_confirm: bool = True):
    """Build a MAC protected ir with its own transactionID and senderNonce (for a batch)."""
    unique = generate_unique_byte_values(length=2, size=16)
    return _mac_protect(
        build_ir_from_key(
            generate_key("ecc"),
            common_name=_SENDER,
            sender=_SENDER,
            implicit_confirm=implicit_confirm,
            for_mac=True,
            pvno=pvno,
            transaction_id=unique[0],
            sender_nonce=unique[1],
        )
    )


class _PvnoAssertions(unittest.TestCase):
    def assert_unsupported_version(self, response):
        """Assert an error, which has `unsupportedVersion` as the only failInfo bit."""
        self.assert_body(response, "error")
        self.assertTrue(
            is_bit_set(get_pkistatusinfo(response)["failInfo"], "unsupportedVersion", exclusive=True),
            display_pki_status_info(response),
        )

    def assert_body(self, response, body_name: str):
        """Assert the body name, and show the status only for an error."""
        info = display_pki_status_info(response) if response["body"].getName() == "error" else ""
        self.assertEqual(response["body"].getName(), body_name, info)

    def assert_accepted(self, response, body_name: str):
        self.assertEqual(response["body"].getName(), body_name, display_pki_status_info(response))
        self.assertEqual(str(get_pkistatusinfo(response)["status"]), "accepted", display_pki_status_info(response))


class TestProcessNormalRequestPvno(_PvnoAssertions):
    @classmethod
    def setUpClass(cls):
        ca_cert, ca_key = load_ca_cert_and_key()
        cls.ca_handler = CAHandler(ca_cert=ca_cert, ca_key=ca_key, pre_shared_secret=_PASSWORD.encode())

    def test_unsupported_pvno_is_rejected(self):
        """
        GIVEN an ir, p10cr, rr and genm with a pvno other than 2 or 3.
        WHEN the request is processed by `process_normal_request`,
        THEN the response is an error with `unsupportedVersion` as the only failInfo bit
        (RFC 9483 Section 3.5: "The pvno MUST be cmp2000(2) or cmp2021(3).").
        """
        for pvno in _UNSUPPORTED_PVNOS:
            rr = build_cmp_revoke_request(serial_number=1, sender=_SENDER, exclude_fields=None, pvno=pvno)
            requests = {
                "ir": _build_ir(pvno),
                "p10cr": _build_p10cr(pvno),
                "rr": _mac_protect(rr),
                "genm": de_and_encode_pkimessage(
                    build_cmp_general_message(add_messages="get_ca_certs", sender=_SENDER, pvno=pvno)
                ),
            }
            for name, request in requests.items():
                with self.subTest(body=name, pvno=pvno):
                    self.assertEqual(int(request["header"]["pvno"]), pvno)
                    self.assert_unsupported_version(self.ca_handler.process_normal_request(request))

    def test_cert_conf_with_unsupported_pvno_is_rejected(self):
        """
        GIVEN an issued certificate and a certConf for it with a pvno other than 2 or 3.
        WHEN the certConf is processed by `process_normal_request`,
        THEN the response is an error with `unsupportedVersion` as the only failInfo bit, and not a later
        failure (RFC 9483 Section 3.5: "The pvno MUST be cmp2000(2) or cmp2021(3).").
        """
        for pvno in _UNSUPPORTED_PVNOS:
            with self.subTest(pvno=pvno):
                response = self.ca_handler.process_normal_request(_build_ir(2, implicit_confirm=False))
                self.assert_accepted(response, "ip")
                cert_conf = _build_cert_conf(response, pvno)
                self.assertEqual(int(cert_conf["header"]["pvno"]), pvno)
                self.assert_unsupported_version(self.ca_handler.process_normal_request(cert_conf))

    def test_nested_inner_unsupported_pvno_is_rejected(self):
        """
        GIVEN an added-protection request with an outer pvno of 2 and an inner ir with a pvno other than 2 or 3.
        WHEN the request is processed by `process_normal_request`,
        THEN the response is an error with `unsupportedVersion` as the only failInfo bit (RFC 9483 Section 3.5).
        """
        ra_key = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")
        ra_cert = parse_certificate(load_and_decode_pem_file("./data/trusted_ras/ra_cms_cert_ecdsa.pem"))
        for pvno in _UNSUPPORTED_PVNOS:
            with self.subTest(pvno=pvno):
                nested = build_nested_pkimessage(other_messages=_build_ir(pvno), for_added_protection=True)
                nested = protect_pkimessage(nested, protection="signature", cert=ra_cert, private_key=ra_key)
                self.assertEqual(int(nested["header"]["pvno"]), 2)
                self.assert_unsupported_version(self.ca_handler.process_normal_request(nested))

    def test_supported_pvno_issues_certificate(self):
        """
        GIVEN an ir with pvno 2 or 3.
        WHEN the request is processed by `process_normal_request`,
        THEN a certificate is issued, so that a gate rejecting everything is detected.
        """
        for pvno in _SUPPORTED_PVNOS:
            with self.subTest(pvno=pvno):
                self.assert_accepted(self.ca_handler.process_normal_request(_build_ir(pvno)), "ip")


class TestChallengePvno(_PvnoAssertions):
    @classmethod
    def setUpClass(cls):
        ca_cert, ca_key = load_ca_cert_and_key()
        cls.ca_handler = CAHandler(ca_cert=ca_cert, ca_key=ca_key, pre_shared_secret=_PASSWORD.encode())

    def test_challenge_popo_with_unsupported_pvno_is_rejected(self):
        """
        GIVEN an ir with a challenge POPO for a x25519 key and for a ML-KEM-768 key.
        WHEN the request has a pvno other than 2 or 3,
        THEN the response is `unsupportedVersion` and not a `popdecc`, which continues the flow.
        With pvno 2 the response stays a `popdecc`.
        """
        for key_name, use_key_enc in (("x25519", False), ("ml-kem-768", True)):
            key = generate_key(key_name)
            for pvno in _UNSUPPORTED_PVNOS:
                with self.subTest(key=key_name, pvno=pvno):
                    ir = _build_ir_with_challenge_popo(key, use_key_enc, pvno)
                    self.assert_unsupported_version(self.ca_handler.process_normal_request(ir))

            with self.subTest(key=key_name, pvno=2):
                response = self.ca_handler.process_normal_request(_build_ir_with_challenge_popo(key, use_key_enc, 2))
                self.assertEqual(response["body"].getName(), "popdecc")


class TestNestedPvno(_PvnoAssertions):
    @classmethod
    def setUpClass(cls):
        ca_cert, ca_key = load_ca_cert_and_key()
        cls.ca_handler = CAHandler(
            ca_cert=ca_cert, ca_key=ca_key, trusted_ras_dir="data/trusted_ras", pre_shared_secret=_PASSWORD.encode()
        )

    def _issued_ip(self):
        """Issue a certificate, which needs a certConf."""
        response = self.ca_handler.process_normal_request(_build_ir_unique(2, implicit_confirm=False))
        self.assert_accepted(response, "ip")
        return response

    def test_outer_unsupported_pvno_of_added_protection_is_rejected(self):
        """
        GIVEN an added-protection request with a valid inner ir (pvno 2).
        WHEN the outer message has a pvno other than 2 or 3,
        THEN the response is an error with `unsupportedVersion` as the only failInfo bit.
        With an outer pvno of 2 a certificate is issued.
        """
        for pvno in _UNSUPPORTED_PVNOS:
            with self.subTest(pvno=pvno):
                nested = _added_protection(_build_ir(2), pvno=pvno)
                self.assertEqual(int(nested["header"]["pvno"]), pvno)
                self.assert_unsupported_version(self.ca_handler.process_normal_request(nested))

        self.assert_accepted(self.ca_handler.process_normal_request(_added_protection(_build_ir(2))), "ip")

    def test_added_protection_cert_conf_with_unsupported_pvno_is_rejected(self):
        """
        GIVEN a certConf inside an added-protection request.
        WHEN the certConf has a pvno other than 2 or 3,
        THEN the response is `unsupportedVersion` and not a `systemFailure`. With pvno 2 the response is a `pkiconf`.
        """
        for pvno in (*_UNSUPPORTED_PVNOS, 2):
            with self.subTest(pvno=pvno):
                cert_conf = _build_cert_conf(self._issued_ip(), pvno)
                response = self.ca_handler.process_normal_request(_added_protection(cert_conf))
                if pvno == 2:
                    self.assert_body(response, "pkiconf")
                else:
                    self.assert_unsupported_version(response)

    def test_batched_cert_conf_with_unsupported_pvno_is_rejected(self):
        """
        GIVEN a batch of two certConf messages.
        WHEN one certConf has a pvno other than 2 or 3,
        THEN the response is `unsupportedVersion` and not a `systemFailure`.
        With pvno 2 the batch is answered with two `pkiconf`.
        """
        for pvno in (*_UNSUPPORTED_PVNOS, 2):
            with self.subTest(pvno=pvno):
                cert_confs = [_build_cert_conf(self._issued_ip(), 2), _build_cert_conf(self._issued_ip(), pvno)]
                response = self.ca_handler.process_normal_request(_batch(cert_confs))
                if pvno == 2:
                    self.assert_body(response, "nested")
                    self.assertEqual([get_cmp_message_type(x) for x in response["body"]["nested"]], ["pkiconf"] * 2)
                else:
                    self.assert_unsupported_version(response)

    def test_batched_added_protection_with_unsupported_pvno_is_rejected(self):
        """
        GIVEN a batch of two added-protection requests with valid inner irs.
        WHEN one of the added-protection messages has a pvno other than 2 or 3,
        THEN the response is `unsupportedVersion`, and no certificate is issued.
        With pvno 2 both certificates are issued.
        """
        for pvno in (*_UNSUPPORTED_PVNOS, 2):
            with self.subTest(pvno=pvno):
                entries = [_added_protection(_build_ir_unique(2), wire=False) for _ in range(2)]
                entries[1] = _added_protection(_build_ir_unique(2), pvno, wire=False)
                batch = _batch(entries, wire=False)
                before = len(self.ca_handler.state.issued_certs)
                response = self.ca_handler.process_normal_request(batch)
                if pvno == 2:
                    self.assert_body(response, "nested")
                    self.assertEqual(len(self.ca_handler.state.issued_certs), before + 2)
                else:
                    self.assert_unsupported_version(response)
                    self.assertEqual(len(self.ca_handler.state.issued_certs), before)

    def test_batch_with_unsupported_pvno_issues_no_certificate(self):
        """
        GIVEN a batch of an ir with pvno 2 and an ir with a pvno other than 2 or 3.
        WHEN the batch is processed,
        THEN the response is `unsupportedVersion` and the first certificate was not issued.
        """
        for pvno in _UNSUPPORTED_PVNOS:
            with self.subTest(pvno=pvno):
                batch = _batch([_build_ir_unique(2), _build_ir_unique(pvno)])
                before = len(self.ca_handler.state.issued_certs)
                self.assert_unsupported_version(self.ca_handler.process_normal_request(batch))
                self.assertEqual(len(self.ca_handler.state.issued_certs), before)


class TestHybridRoutesPvno(_PvnoAssertions):
    @classmethod
    def setUpClass(cls):
        ca_cert, ca_key = load_ca_cert_and_key()
        cls.ca_handler = CAHandler(ca_cert=ca_cert, ca_key=ca_key, pre_shared_secret=_PASSWORD.encode())
        # The module global `handler` only exists when the Mock CA is started as a script.
        patcher = mock.patch.object(ca_handler, "handler", cls.ca_handler, create=True)
        patcher.start()
        cls.addClassCleanup(patcher.stop)
        cls.client = ca_handler.app.test_client()

    def _post(self, route: str, request):
        result = self.client.post(route, data=try_encode_pyasn1(request, exclude_pretty_print=True))
        self.assertEqual(result.status_code, 200, f"{route}: {result.data[:200]!r}")
        return parse_pkimessage(result.data)

    def test_unsupported_pvno_is_rejected_on_every_route(self):
        """
        GIVEN a MAC protected p10cr with a pvno other than 2 or 3.
        WHEN it is posted to each hybrid route (for /chameleon with a paired CSR),
        THEN the response is an error with `unsupportedVersion` as the only failInfo bit
        (RFC 9483 Section 3.5: "The pvno MUST be cmp2000(2) or cmp2021(3).").
        """
        for pvno in _UNSUPPORTED_PVNOS:
            for route in _ALL_ROUTES:
                with self.subTest(route=route, pvno=pvno):
                    request = _build_paired_p10cr(pvno) if route == "/chameleon" else _build_p10cr(pvno)
                    self.assert_unsupported_version(self._post(route, request))

    def test_cert_conf_with_unsupported_pvno_is_rejected(self):
        """
        GIVEN a certificate issued over /catalyst-sig and a certConf for it with a pvno other than 2 or 3.
        WHEN the certConf is posted to each route which handles a certConf,
        THEN the response is an error with `unsupportedVersion` as the only failInfo bit
        (RFC 9483 Section 3.5: "The pvno MUST be cmp2000(2) or cmp2021(3).").
        """
        for pvno in _UNSUPPORTED_PVNOS:
            for route in _CERT_CONF_ROUTES:
                with self.subTest(route=route, pvno=pvno):
                    response = self._post("/catalyst-sig", _build_p10cr(2, implicit_confirm=False))
                    self.assert_accepted(response, "cp")
                    self.assert_unsupported_version(self._post(route, _build_cert_conf(response, pvno)))

    def test_supported_pvno_issues_certificate(self):
        """
        GIVEN a MAC protected request with pvno 2 or 3.
        WHEN it is posted to /chameleon (paired CSR) and to /catalyst-sig,
        THEN a certificate is issued, so that a gate rejecting everything is detected.
        """
        for pvno in _SUPPORTED_PVNOS:
            with self.subTest(route="/chameleon", pvno=pvno):
                self.assert_accepted(self._post("/chameleon", _build_paired_p10cr(pvno)), "cp")
            with self.subTest(route="/catalyst-sig", pvno=pvno):
                self.assert_accepted(self._post("/catalyst-sig", _build_p10cr(pvno)), "cp")
