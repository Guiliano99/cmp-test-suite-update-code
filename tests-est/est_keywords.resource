# SPDX-FileCopyrightText: Copyright 2025 Siemens AG   # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
*** Settings ***
Documentation       High-level keywords and configuration for the EST (Enrollment over Secure
...                 Transport, RFC 7030) test suite. Wires the `resources/est_utils.py` protocol
...                 logic together with HTTP transport so EST flows can be exercised both offline
...                 (message-level) and against a live EST server (the Mock CA exposes the
...                 `/.well-known/est/*` endpoints, see `mock_ca/est_handler.py`).

Library             Collections
Library             OperatingSystem
Library             String
Library             RequestsLibrary
Library             ../resources/est_utils.py
Library             ../resources/keyutils.py


*** Variables ***
# --- EST server under test --------------------------------------------------
# Scheme + authority of the EST server. EST mandates TLS (RFC 7030 Section 3.3),
# so this is normally an https:// URL. The Mock CA serves EST over plain HTTP for
# local testing, so the default points at it.
${EST_BASE_URL}             http://127.0.0.1:5000
# Optional additional path segment (RFC 7030 Section 3.2.2) to select a CA /
# enrollment profile, e.g. "RSA". ${None} means no label.
${EST_LABEL}                ${None}
# Whether the test TLS server certificate should be verified.
${EST_VERIFY_TLS}           ${False}
# Default key algorithm used when generating client keys for enrollment tests.
${EST_CLIENT_KEY_ALG}       ec

# --- Bundled RFC test vectors (see data/generate_est_vectors.py) ------------
${EST_DATA_DIR}             ${CURDIR}/data
${EST_CACERTS_VECTOR}       ${EST_DATA_DIR}/est_cacerts.p7b
${EST_CSR_VECTOR}           ${EST_DATA_DIR}/est_simpleenroll.csr
${EST_CA_CERT_VECTOR}       ${EST_DATA_DIR}/est_ca_cert.pem


*** Keywords ***
Load EST Test Vector
    [Documentation]    Read a bundled EST test-vector file and return its raw bytes.
    [Arguments]    ${path}
    ${data}=    Get Binary File    ${path}
    RETURN    ${data}

Build EST URL
    [Documentation]    Convenience wrapper that applies the configured ${EST_LABEL}.
    [Arguments]    ${operation}
    ${url}=    Get EST Endpoint URL    ${EST_BASE_URL}    ${operation}    label=${EST_LABEL}
    RETURN    ${url}

EST Response Must Use Content Type
    [Documentation]    Assert that an HTTP response carries the media type required by RFC 7030
    ...                for the given operation direction.
    [Arguments]    ${response}    ${expected_content_type}
    ${actual}=    Get From Dictionary    ${response.headers}    Content-Type
    ${ok}=    EST Content Type Matches    ${actual}    ${expected_content_type}
    Should Be True    ${ok}
    ...    msg=Expected Content-Type '${expected_content_type}', got '${actual}'

Generate EST Client CSR
    [Documentation]    Generate a fresh client key and PKCS#10 CSR for enrollment, returning
    ...                the ``(key, csr)`` pair.
    [Arguments]    ${common_name}=CN=EST Test Client    ${algorithm}=${EST_CLIENT_KEY_ALG}
    ${key}=    Generate Key    ${algorithm}
    ${csr}=    Build EST CSR    ${key}    ${common_name}
    RETURN    ${key}    ${csr}

Send EST CACerts Request
    [Documentation]    RFC 7030 Section 4.1: GET /cacerts. Returns the requests response object.
    ${url}=    Build EST URL    cacerts
    ${resp}=    GET    ${url}    expected_status=any    verify=${EST_VERIFY_TLS}
    RETURN    ${resp}

Send EST CSR Attributes Request
    [Documentation]    RFC 7030 Section 4.5: GET /csrattrs. Returns the requests response object.
    ${url}=    Build EST URL    csrattrs
    ${resp}=    GET    ${url}    expected_status=any    verify=${EST_VERIFY_TLS}
    RETURN    ${resp}

Send EST Enroll Request
    [Documentation]    RFC 7030 Section 4.2: POST /simpleenroll or /simplereenroll with a base64
    ...                PKCS#10 body. Returns the requests response object.
    [Arguments]    ${csr}    ${operation}=simpleenroll
    ${url}=    Build EST URL    ${operation}
    ${body}=    Build EST Enroll Request Body    ${csr}
    &{headers}=    Create Dictionary
    ...    Content-Type=application/pkcs10    Content-Transfer-Encoding=base64
    ${resp}=    POST    ${url}    data=${body}    headers=${headers}
    ...    expected_status=any    verify=${EST_VERIFY_TLS}
    RETURN    ${resp}

Send EST Server Keygen Request
    [Documentation]    RFC 7030 Section 4.4: POST /serverkeygen with a base64 PKCS#10 body.
    ...                Returns the requests response object.
    [Arguments]    ${csr}
    ${url}=    Build EST URL    serverkeygen
    ${body}=    Build EST Enroll Request Body    ${csr}
    &{headers}=    Create Dictionary
    ...    Content-Type=application/pkcs10    Content-Transfer-Encoding=base64
    ${resp}=    POST    ${url}    data=${body}    headers=${headers}
    ...    expected_status=any    verify=${EST_VERIFY_TLS}
    RETURN    ${resp}
