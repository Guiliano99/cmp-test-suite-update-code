<!--
SPDX-FileCopyrightText: Copyright 2025 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# `tests-est` — Enrollment over Secure Transport (EST) Tests

This folder provides a self-contained, in-depth test bed for the **EST**
protocol ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030), with
[RFC 8951](https://www.rfc-editor.org/rfc/rfc8951) /
[RFC 8295](https://www.rfc-editor.org/rfc/rfc8295) /
[RFC 7894](https://www.rfc-editor.org/rfc/rfc7894)). It mirrors the layout of
the other test directories in this suite (`tests/`, `tests_pq_and_hybrid/`,
`tests_mock_ca/`): Robot Framework suites driven by minimal Python "logic"
modules.

The goal is to make every EST operation testable at two depths:

1. **Message level (offline)** — build, encode, decode, and validate EST
   messages without a server. These tests run in CI and require no network.
2. **Server level (opt-in)** — drive a live EST server over TLS end-to-end.

## Contents

| File | Purpose |
| --- | --- |
| `est.robot` | The in-depth EST test suite, organized by RFC 7030 section. |
| `est_keywords.resource` | High-level keywords, configuration variables, and HTTP transport. |
| `est_logic.py` | Minimal Python primitives (URL/path, transfer encoding, content types, CMS certs-only parsing, `/csrattrs`). Robot keywords exposed via `@keyword`. |
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

| Section | Operation | Offline | Server |
| --- | --- | :---: | :---: |
| 3.2.2 | Well-known URI & paths | ✅ | — |
| 3.2.4 | Media types | ✅ | ✅ |
| 3.2 / RFC 8951 | base64 transfer encoding | ✅ | — |
| 4.1 | `/cacerts` | ✅ | ✅ |
| 4.2 | `/simpleenroll`, `/simplereenroll` | ✅ | _planned_ |
| 4.4 | `/serverkeygen` | _planned_ | _planned_ |
| 4.5 | `/csrattrs` | ✅ | _planned_ |

"_planned_" entries are scaffolded in `est_logic.py` / `est_keywords.resource`
and are intended as the next increments.

## Running the tests

Offline message-level tests only (CI-safe, no server needed):

```bash
robot --pythonpath ./tests-est --exclude est-server --outputdir reports tests-est/est.robot
```

End-to-end against a live EST server — point `EST_BASE_URL` at it (and set
`EST_VERIFY_TLS` / `EST_LABEL` as needed):

```bash
robot --pythonpath ./tests-est \
      --variable EST_BASE_URL:https://my-est-host:8443 \
      --variable EST_VERIFY_TLS:False \
      --outputdir reports tests-est/est.robot
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
| `${EST_BASE_URL}` | `https://127.0.0.1:8443` | Scheme + authority of the EST server. |
| `${EST_LABEL}` | `${None}` | Optional RFC 7030 §3.2.2 path label (CA/profile selector). |
| `${EST_VERIFY_TLS}` | `${False}` | Whether to verify the server's TLS certificate. |
| `${EST_DATA_DIR}` | `${CURDIR}/data` | Location of the bundled test vectors. |
