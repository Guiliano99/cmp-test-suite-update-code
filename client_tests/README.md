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

1. Install dependencies:
    ```bash
    pip install uv && uv sync
    ```
2. Start CA server:
   ```bash
   python3 mock_ca/ca_handler.py 
   ```
3. Run tests:
   ```bash
   cd client_tests
   robot cmp_tests_jinja.robot
   ```
## Add Custom Client
1. Define your cmp commands in the test suit: Default is Openssl:
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
        -ref {{ ref | default('NULL-DN') }}
        {% if recipient %}-recipient {{ recipient }}{% endif %}
        {% if csr %}-csr {{ csr }}{% endif %}
        {% if newkey %}-newkey {{ newkey }}{% endif %}
        {% if certout %}-certout {{ certout }}{% endif %}
        {% if unprotected_requests %}-unprotected_requests{% endif %}
        """
   ```

## gencmpclient-rs

A ready-made command template for the Rust reference client
[`gencmpclient-rs`](https://github.com/Guiliano99/gencmpclient-rs) is included
(`gencmpclient_rs` in `cmp_client.py`).

1. Build the client (`cargo build --release` in the `gencmpclient-rs` checkout).
2. Tell the suite where the binary is (defaults to
   `../../gencmpclient-rs/target/release/gencmpclient-rs` relative to
   `client_tests/`):
   ```bash
   export GENCMPCLIENT_RS_BIN=/path/to/gencmpclient-rs/target/release/gencmpclient-rs
   ```
3. Start the Mock CA and run the suite selecting the Rust client. `kur`/`rr` are
   stubbed in the client, so disable those positive tests:
   ```bash
   python3 mock_ca/ca_handler.py            # freshly started
   cd client_tests
   robot --variable CMP_CLIENT:gencmpclient_rs \
         --variable CLIENT_SUPPORTS_KUR:False \
         --variable CLIENT_SUPPORTS_RR:False \
         cmp_tests_jinja.robot
   ```

The `${CLIENT_SUPPORTS_KUR}` / `${CLIENT_SUPPORTS_RR}` variables gate the positive
key-update / revocation tests; set them to `True` for a client that implements
those commands.
