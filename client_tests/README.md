<!--
SPDX-FileCopyrightText: Copyright 2025 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

This folder contains an experimental draft for test cases of client-side
CMP implementations.

- `cmp_tests_jinja.robot`: Main test suite for client-side components.
- `certs`: Contains all required certificates for testing.
- `cmp_client.py`: Defines the commands for CMP clients.


## Running Tests

1. Install dependencies (from the repository root):
    ```bash
    pip install uv && uv sync
    ```
2. Start the mock CA server (from the repository root):
   ```bash
   uv run python mock_ca/ca_handler.py --allow-same-key
   ```
   The `--allow-same-key` option permits repeated enrollment with the same key,
   which is needed when re-running the tests (they use fixed keys and CSRs)
   without restarting the mock CA in between.
3. Run tests (with the default client, the OpenSSL CMP app):
   ```bash
   cd client_tests
   robot cmp_tests_jinja.robot
   ```

## Testing genCMPClient (cmpClient)

The suite can drive the `cmpClient` CLI of
[genCMPClient](https://github.com/siemens/gencmpclient) as the client under test.

1. Build genCMPClient in a sibling checkout of this repository:
   ```bash
   cd ../gencmpclient
   git submodule update --init --depth 1 libsecutils cmpossl
   make -f Makefile_v1 build USE_LIBCMP=1
   ```
   Building with `USE_LIBCMP=1` is required for the positive p10cr test:
   the mock CA checks, as specified in RFC 9483 Section 3.1, that with MAC-based
   protection the senderKID equals the commonName of the sender field, which for
   p10cr requires the RFC 9483 senderKID default provided by the intermediate
   CMP library (cmpossl) but not by OpenSSL itself. For the same reason,
   `P10CR 03 - Valid P10CR With CSR Should Pass` cannot pass with the plain
   `openssl cmp` app.
2. Start the mock CA as described above.
3. Run the tests with `cmpClient` as the client under test:
   ```bash
   cd client_tests
   robot --variable CMP_CLIENT:gencmpclient cmp_tests_jinja.robot
   ```
   If genCMPClient is not a sibling checkout, override the binary and library
   locations, e.g.:
   ```bash
   robot --variable CMP_CLIENT:gencmpclient \
         --variable CMP_CLIENT_BIN:/path/to/gencmpclient/cmpClient \
         --variable CMP_CLIENT_LIB:/path/to/gencmpclient \
         cmp_tests_jinja.robot
   ```

genCMPClient also ships a ready-made config file for manual runs against the
mock CA: see `config/test_suite.cnf` in the genCMPClient repository.

## Add Custom Client
1. Define your cmp commands in the test suite: Default is Openssl:
```bash
    ${CMP_CLIENT}    openssl
    ${INITIATION_REQUEST}      ir
    ${CERTIFICATION_REQUEST}   p10cr
    ${KEY_UPDATE_REQUEST}      kur
    ${REVOCATION_REQUEST}      rr
```
2. Define all available CLI commands for your cmp client in "cmp_client.py" using jinja, example of openssl:
   ```python
    openssl = """
        openssl cmp
        -cmd {{ cmd }}
        -server {{ server }}
        -subject {{ subject }}
        -secret {{ secret }}
        {% if ref %}-ref {{ ref }}{% endif %}
        {% if recipient %}-recipient "{{ recipient }}"{% endif %}
        {% if csr %}-csr {{ csr }}{% endif %}
        {% if newkey %}-newkey {{ newkey }}{% endif %}
        {% if certout %}-certout {{ certout }}{% endif %}
        {% if implicit_confirm %}-implicit_confirm{% endif %}
        {% if unprotected_requests %}-unprotected_requests{% endif %}
        """
   ```
   The rendered command is split with `shlex.split`, so values containing
   spaces (such as `-recipient "/CN=Mock CA"`) must be quoted in the template.
