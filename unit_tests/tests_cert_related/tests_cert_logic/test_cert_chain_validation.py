# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from typing import List
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480
from resources import certutils
from resources.certutils import verify_cert_chain_openssl
from resources.exceptions import BadConfig
from resources.keyutils import load_private_key_from_file

from unit_tests.utils_for_test import load_or_generate_cert_chain


class TestVerifyCertChainOpenssl(unittest.TestCase):
    def setUp(self):
        cert_chain, _ = load_or_generate_cert_chain()
        self.cert_chain: List[rfc9480.CMPCertificate] = cert_chain
        self.root_cert = self.cert_chain[0]
        self.ca1_cert = self.cert_chain[1]
        self.ca2_cert = self.cert_chain[2]
        # expects the chain to start from the end-entity
        self.cert_chain = cert_chain[::-1]

    def test_verify_single_cert(self):
        """
        GIVEN a valid self-signed certificate
        WHEN the chain is validated using OpenSSL,
        THEN the chain should be successfully validated without any errors
        """
        verify_cert_chain_openssl([self.root_cert])

    def test_verify_two_certs(self):
        """
        GIVEN a valid certificate chain (Intermediate, Root)
        WHEN the chain is validated using OpenSSL,
        THEN the chain should be successfully validated without any errors
        """
        verify_cert_chain_openssl([self.ca1_cert, self.root_cert])

    def test_verify_three_certs(self):
        """
        GIVEN a valid certificate chain (End-Entity, Intermediate, Root)
        WHEN the chain is validated using OpenSSL,
        THEN the chain should be successfully validated without any errors
        """
        verify_cert_chain_openssl([self.ca2_cert, self.ca1_cert, self.root_cert])

    def test_verify_more_certs(self):
        """
        GIVEN a valid certificate chain starting from End-Entity, to Root, with length 6.
        WHEN the chain is validated using OpenSSL,
        THEN the chain should be successfully validated without any errors
        """
        verify_cert_chain_openssl(self.cert_chain)

    def test_crl_check_survives_concurrent_verify(self):
        """
        GIVEN a valid certificate chain (Intermediate, Root) and a valid CRL of the Root, fetched over HTTP,
        WHEN a second validation without CRL check finishes right before the first one runs OpenSSL,
        THEN the first validation still finds its own CRL file and succeeds without any errors.
        """
        root_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
        now = datetime.now(timezone.utc)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(x509.load_der_x509_certificate(encoder.encode(self.root_cert)).subject)
            .last_update(now - timedelta(minutes=5))
            .next_update(now + timedelta(days=1))
            .sign(root_key, None)
        )
        response = MagicMock(content=crl.public_bytes(serialization.Encoding.DER))
        chain = [self.ca1_cert, self.root_cert]
        real_run = subprocess.run

        def _other_caller_first(cmd, *args, **kwargs):
            # Only the outer call passes -CRLfile, so the nested call runs OpenSSL directly.
            if "-CRLfile" in cmd:
                verify_cert_chain_openssl(chain)
            return real_run(cmd, *args, **kwargs)

        with (
            patch.object(certutils, "_extract_crl_urls_from_cert_pyasn1", return_value=["http://crl.invalid/root.crl"]),
            patch.object(certutils.requests, "get", return_value=response),
            patch.object(certutils.subprocess, "run", side_effect=_other_caller_first),
        ):
            verify_cert_chain_openssl(chain, crl_check=True)

    def test_missing_openssl_binary_is_a_config_error(self):
        """
        GIVEN a valid certificate chain (Intermediate, Root) and a `PATH` without an `openssl` binary,
        WHEN the chain is validated using OpenSSL,
        THEN `BadConfig` is raised, not the trust verdict `SignerNotTrusted`.
        """
        with tempfile.TemporaryDirectory() as empty_dir, patch.dict(os.environ, {"PATH": empty_dir}):
            with self.assertRaises(BadConfig):
                verify_cert_chain_openssl([self.ca1_cert, self.root_cert])
