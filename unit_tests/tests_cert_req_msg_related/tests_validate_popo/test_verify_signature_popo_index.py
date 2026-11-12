# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.ca_ra_utils import build_cp_cmp_message, verify_popo_for_cert_request
from resources.certutils import parse_certificate
from resources.cmputils import build_cr_from_key, prepare_cert_req_msg
from resources.exceptions import BadPOP
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestVerifySignaturePopoIndex(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))
        cls.key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
        cls.key2 = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    def _build_cr(self, bad_first: bool, bad_second: bool):
        """Build a `cr` with two signature-POP requests, each one optionally with an invalid POP."""
        first = prepare_cert_req_msg(private_key=self.key, cert_req_id=0, common_name="CN=First", bad_pop=bad_first)
        second = prepare_cert_req_msg(private_key=self.key2, cert_req_id=1, common_name="CN=Second", bad_pop=bad_second)
        return build_cr_from_key(signing_key=None, cert_req_msg=[first, second])

    def test_verify_popo_checks_the_given_request(self):
        """
        GIVEN a `cr` whose first `CertReqMsg` has a valid and whose second has an invalid signature POP.
        WHEN the POP of the second request is verified.
        THEN must a `BadPOP` be raised.
        """
        pki_message = self._build_cr(bad_first=False, bad_second=True)
        with self.assertRaises(BadPOP):
            verify_popo_for_cert_request(pki_message, cert_req_index=1, verify_ra_verified=False)

    def test_verify_popo_ignores_other_requests(self):
        """
        GIVEN a `cr` whose first `CertReqMsg` has an invalid and whose second has a valid signature POP.
        WHEN the POP of the second request is verified.
        THEN must the verification succeed.
        """
        pki_message = self._build_cr(bad_first=True, bad_second=False)
        verify_popo_for_cert_request(pki_message, cert_req_index=1, verify_ra_verified=False)

    def test_cp_is_not_built_for_a_bad_second_pop(self):
        """
        GIVEN a `cr` whose first `CertReqMsg` has a valid and whose second has an invalid signature POP.
        WHEN the `cp` response is built for all requests.
        THEN must a `BadPOP` be raised and no certificate be issued.
        """
        pki_message = self._build_cr(bad_first=False, bad_second=True)
        with self.assertRaises(BadPOP):
            build_cp_cmp_message(request=pki_message, ca_key=self.ca_key, ca_cert=self.ca_cert)


if __name__ == "__main__":
    unittest.main()
