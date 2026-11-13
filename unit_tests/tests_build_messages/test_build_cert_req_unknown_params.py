# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_csr
from resources.cmputils import (
    build_ccr_from_csr,
    build_ccr_from_key,
    build_cr_from_csr,
    build_cr_from_key,
    build_ir_from_csr,
    build_ir_from_key,
    build_key_update_request,
    build_krr_from_key,
)
from resources.keyutils import load_private_key_from_file

# The PKIHeader keys every builder hands to the shared PKIMessage code, with their default values.
_HEADER_PARAMS = {
    "transaction_id": None,
    "sender_nonce": None,
    "recip_nonce": None,
    "recip_kid": None,
    "implicit_confirm": False,
    "sender_kid": None,
    "pvno": 2,
    "for_mac": False,
    "message_time": None,
}

# The `CertReqMsg` keys every builder accepts in `**params`, with their default values
# (Build Cr From CSR accepts `bad_pop` but does not read it).
_REQ_PARAMS = {
    "cert_req_id": 0,
    "hash_alg": "sha256",
    "extensions": None,
    "controls": None,
    "ra_verified": False,
    "for_kga": False,
    "popo": None,
    "bad_pop": False,
}


class TestBuildCertReqUnknownParams(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        csr = build_csr(cls.key, common_name="CN=Hans the Tester")
        # RF keyword name -> (builder call, the extra keys only this builder reads, with their default values).
        cls.builders = {
            "Build Key Update Request": (
                lambda **kw: build_key_update_request(cls.key, **kw),
                {"cert_template": None, "spki": None, "include_cert_extensions": False},
            ),
            "Build Ir From Key": (
                lambda **kw: build_ir_from_key(cls.key, **kw),
                {"cert_template": None, "cert_request": None, "spki": None},
            ),
            "Build Cr From Key": (lambda **kw: build_cr_from_key(cls.key, **kw), {"cert_template": None}),
            "Build Krr From Key": (lambda **kw: build_krr_from_key(cls.key, **kw), {"cert_template": None}),
            "Build Ccr From Key": (lambda **kw: build_ccr_from_key(cls.key, **kw), {"cert_template": None}),
            "Build Ir From CSR": (lambda **kw: build_ir_from_csr(csr, cls.key, **kw), {}),
            "Build Cr From CSR": (lambda **kw: build_cr_from_csr(csr, cls.key, **kw), {}),
            "Build Ccr From CSR": (lambda **kw: build_ccr_from_csr(csr, cls.key, **kw), {}),
        }

    def test_misspelled_param_is_rejected(self):
        """
        GIVEN each of the eight certificate request builders.
        WHEN it is called with the misspelled argument `exclude_field` instead of `exclude_fields`.
        THEN it raises a `ValueError` that names the unknown argument.
        """
        for name, (build, _) in self.builders.items():
            with self.subTest(keyword=name):
                with self.assertRaisesRegex(ValueError, r"\['exclude_field'\]"):
                    build(exclude_field="sender,senderKID")

    def test_documented_params_are_accepted(self):
        """
        GIVEN each of the eight certificate request builders.
        WHEN it is called with every key it reads from `**params` and `exclude_fields="sender,senderKID"`.
        THEN it builds the request, and the header has no `senderKID`.
        """
        for name, (build, extra) in self.builders.items():
            with self.subTest(keyword=name):
                pki_message = build(exclude_fields="sender,senderKID", **_HEADER_PARAMS, **_REQ_PARAMS, **extra)
                self.assertFalse(pki_message["header"]["senderKID"].isValue)


if __name__ == "__main__":
    unittest.main()
