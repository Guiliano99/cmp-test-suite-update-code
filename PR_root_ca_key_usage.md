<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# fix(certificates): Add missing Key Usage extension to Root CA certificate

Regenerate the Root CA certificate (Ed25519) across all data directories and update the test utility that generates 
it at runtime to include the correct `Key Usage` extension.

## Description

**Changed files:**
- `data/mock_ca/trustanchors/root_cert_ed25519.pem` — regenerated with `keyCertSign`, `cRLSign`, and `digitalSignature` set
- `data/trustanchors/root_cert_ed25519.pem` — same
- `data/unittest/root_cert_ed25519.pem` — same
- `data/unittest/test_cert_chain_len6.pem` — chain certificate regenerated to match updated root
- `unit_tests/utils_for_test.py` — `_prepare_root_ca_extensions()` now passes `key_usage="digitalSignature,keyCertSign,cRLSign"` to `_prepare_ca_ra_extensions()`

## Motivation and Context

- OpenSSL rejects CA certificates that are missing a `Key Usage` extension (or that have one without `keyCertSign`) when performing certificate chain validation, unless the strict check is explicitly disabled with a flag.
- This error occurs, because the PKIMessage is currently singed by the RootCA cert for easyness.

## How Has This Been Tested?

- Verified with OpenSSL.
