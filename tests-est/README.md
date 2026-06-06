<!--
SPDX-FileCopyrightText: Copyright 2025 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# `tests-est` — Enrollment over Secure Transport (EST) Tests

This folder provides an in-depth test bed for the **EST** protocol
([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030), with
[RFC 8951](https://www.rfc-editor.org/rfc/rfc8951) /
[RFC 8295](https://www.rfc-editor.org/rfc/rfc8295) /
[RFC 7894](https://www.rfc-editor.org/rfc/rfc7894)). EST is implemented on top
of the suite's existing functionality and is split across three layers:

| Layer | Location | Role |
| --- | --- | --- |
| Protocol logic | [`../resources/est_utils.py`](../resources/est_utils.py) | Shared message layer: well-known URL/path, base64 transfer encoding, content types, PKCS#10 building, `certs-only` CMS build/parse, `CsrAttrs`, and `/serverkeygen` multipart. Reuses `certbuildutils`, `certutils`, `envdatautils`, `keyutils`. |
| Server | [`../mock_ca/est_handler.py`](../mock_ca/est_handler.py) | `EstHandler` — issues certificates from CSRs via `certbuildutils.build_cert_from_csr`. Wired into the Mock CA Flask app under `/.well-known/est/*` (see `../mock_ca/ca_handler.py`), sharing its CA key/cert, chain, extensions and issued-cert state. |
| Client / tests | this folder | Robot Framework suite driving both message-level and live-server flows. |

The implementation can be tested at two depths:

1. **Message level (offline)** — build, encode, decode, and validate EST
   messages without a server (CI-safe, no network).
2. **Server level** — drive the Mock CA's EST endpoints end-to-end.

## Contents

| File | Purpose |
| --- | --- |
| `est.robot` | The in-depth EST test suite, organized by RFC 7030 section. |
| `est_keywords.resource` | High-level keywords, configuration variables, and HTTP transport. |
| `REFERENCES.md` | EST RFCs and the foundational standards they build on. |
| `data/` | Bundled RFC test vectors and the script that generates them. |

### Test vectors (`data/`)

| File | Description |
| --- | --- |
| `est_cacerts.p7b` | RFC 7030 §4.1.3 `/cacerts` response — base64 certs-only CMS `SignedData`. |
| `est_simpleenroll.csr` | RFC 7030 §4.2.1 `/simpleenroll` request body — base64 PKCS#10. |
| `est_ca_cert.pem` / `est_ca_key.pem` | The self-signed test CA inside the bundle. |
| `est_client_key.pem` | Private key matching the sample CSR. |
| `generate_est_vectors.py` | Regenerates all of the above (uses `cryptography`). |

Regenerate the vectors with:

```bash
python tests-est/data/generate_est_vectors.py
```

## Coverage vs. RFC 7030

| Section | Operation | Implemented | Offline test | Server test |
| --- | --- | :---: | :---: | :---: |
| 3.2.2 | Well-known URI & paths | ✅ | ✅ | — |
| 3.2.4 | Media types | ✅ | ✅ | ✅ |
| 3.2 / RFC 8951 | base64 transfer encoding | ✅ | ✅ | — |
| 4.1 | `/cacerts` | ✅ | ✅ | ✅ |
| 4.2.1 | `/simpleenroll` | ✅ | ✅ | ✅ |
| 4.2.2 | `/simplereenroll` | ✅ | — | ✅ |
| 4.4 | `/serverkeygen` | ✅ | — | ✅ |
| 4.5 | `/csrattrs` | ✅ | ✅ | ✅ |
| 4.3 | `/fullcmc` | content type only | — | — |

## Running the tests

### Offline message-level tests (CI-safe, no server)

```bash
robot --pythonpath ./ --exclude est-server --outputdir reports tests-est/est.robot
```

### Against the Mock CA

Start the Mock CA (it now serves the EST endpoints) and run the full suite:

```bash
python ./mock_ca/ca_handler.py --port 5000 &
robot --pythonpath ./ \
      --variable EST_BASE_URL:http://127.0.0.1:5000 \
      --outputdir reports tests-est/est.robot
```

### Python unit tests

EST is also covered by fast, server-less unit tests:

```bash
# Direct handler tests (no PQ deps required)
python -m unittest unit_tests.tests_experimental_and_mock_ca.tests_mock_ca.test_est_handler
# Flask route integration (real CAHandler)
python -m unittest unit_tests.tests_experimental_and_mock_ca.test_est_routes
```

### Tags

| Tag | Meaning |
| --- | --- |
| `est` | All tests in this suite (forced tag). |
| `est-offline` | Runs without a server. |
| `est-server` | Requires a reachable EST server at `EST_BASE_URL`. |
| `rfc7030-<section>`, `rfc8951` | Pinpoint the governing specification. |

## Configuration variables

Defined in `est_keywords.resource` and overridable on the command line:

| Variable | Default | Meaning |
| --- | --- | --- |
| `${EST_BASE_URL}` | `http://127.0.0.1:5000` | Scheme + authority of the EST server. |
| `${EST_LABEL}` | `${None}` | Optional RFC 7030 §3.2.2 path label (CA/profile selector). |
| `${EST_VERIFY_TLS}` | `${False}` | Whether to verify the server's TLS certificate. |
| `${EST_CLIENT_KEY_ALG}` | `ec` | Key algorithm used for generated client enrollment keys. |
| `${EST_DATA_DIR}` | `${CURDIR}/data` | Location of the bundled test vectors. |
