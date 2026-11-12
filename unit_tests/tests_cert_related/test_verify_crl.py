# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from resources import certutils
from resources.certutils import (
    build_crl_chain_from_list,
    find_crl_signer_cert,
    load_certificates_from_dir,
    parse_crl,
    parse_certificate,
    verify_openssl_crl,
)
from resources.exceptions import BadConfig
from resources.utils import load_and_decode_pem_file

from unit_tests.utils_for_test import compare_pyasn1_objects


class TestCRLSignatureVerification(unittest.TestCase):

    def setUp(self):
        self.crl_path = "data/unittest/test_verify_crl.crl"
        der_data = load_and_decode_pem_file(self.crl_path)
        self.crl_obj = parse_crl(der_data)
        self.crl_signer = parse_certificate(
            load_and_decode_pem_file("data/unittest/crl_sign_cert_ecdsa.pem"))

        self.root_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))

    def test_find_crl(self):
        """
        GIVEN a CRL with a valid signature.
        WHEN a directory containing certificates is provided,
        THEN the CRL signer should be successfully found.
        """
        signer = find_crl_signer_cert(self.crl_obj, ca_cert_dir="data/unittest")
        self.assertTrue(compare_pyasn1_objects(signer, self.crl_signer))

    def test_build_crl_chain(self):
        """
        GIVEN a CRL with a valid signature.
        WHEN the CRL chain is built,
        THEN the CRL chain should be successfully built.
        """
        certs = load_certificates_from_dir("data/unittest")
        crl_chain = build_crl_chain_from_list(self.crl_obj, certs=certs)
        self.assertEqual(len(crl_chain), 3)
        self.assertTrue(compare_pyasn1_objects(crl_chain[0], self.crl_obj))
        self.assertTrue(compare_pyasn1_objects(crl_chain[1], self.crl_signer))
        self.assertTrue(compare_pyasn1_objects(crl_chain[2], self.root_cert))


    def test_crl_signature_verification(self):
        """
        GIVEN a CRL with a valid signature.
        WHEN the CRL is verified using OpenSSL.
        THEN the CRL should be successfully verified.
        """
        certs = load_certificates_from_dir("data/unittest")
        crl_chain = build_crl_chain_from_list(self.crl_obj, certs=certs)
        verify_openssl_crl(crl_chain)

    def test_crl_verification_survives_concurrent_verification(self):
        """
        GIVEN a CRL with a valid signature.
        WHEN a second CRL verification finishes right before the first one runs OpenSSL,
        THEN the first verification still finds its own files and the CRL is successfully verified.
        """
        certs = load_certificates_from_dir("data/unittest")
        real_run = subprocess.run
        calls = []

        def _other_caller_first(cmd, *args, **kwargs):
            if not calls:
                calls.append(cmd)
                verify_openssl_crl(build_crl_chain_from_list(self.crl_obj, certs=certs))
            return real_run(cmd, *args, **kwargs)

        with patch.object(certutils.subprocess, "run", side_effect=_other_caller_first):
            verify_openssl_crl(build_crl_chain_from_list(self.crl_obj, certs=certs))

    def test_missing_openssl_binary_is_a_config_error(self):
        """
        GIVEN a CRL with a valid signature and a `PATH` without an `openssl` binary.
        WHEN the CRL is verified using OpenSSL.
        THEN `BadConfig` is raised, not the verdict `ValueError`.
        """
        crl_chain = build_crl_chain_from_list(self.crl_obj, certs=load_certificates_from_dir("data/unittest"))
        with tempfile.TemporaryDirectory() as empty_dir, patch.dict(os.environ, {"PATH": empty_dir}):
            with self.assertRaises(BadConfig):
                verify_openssl_crl(crl_chain)


if __name__ == "__main__":
    unittest.main()
