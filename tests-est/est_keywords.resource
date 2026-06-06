# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       High-level keywords and configuration for the EST (Enrollment over Secure
...                 Transport, RFC 7030) test suite. Wires the minimal `est_logic.py` primitives
...                 together with HTTP transport so EST flows can be exercised both offline
...                 (message-level) and against a live EST server.

Library             Collections
Library             OperatingSystem
Library             String
Library             RequestsLibrary
Library             est_logic.py


*** Variables ***
# --- EST server under test --------------------------------------------------
# Scheme + authority of the EST server. EST mandates TLS (RFC 7030 Section 3.3),
# so this is normally an https:// URL. Override per environment.
${EST_BASE_URL}             https://127.0.0.1:8443
# Optional additional path segment (RFC 7030 Section 3.2.2) to select a CA /
# enrollment profile, e.g. "RSA". ${None} means no label.
${EST_LABEL}                ${None}
# Whether the test TLS server certificate should be verified. For a local mock
# server this is usually False; against a real CA point it at a trust anchor.
${EST_VERIFY_TLS}           ${False}

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

Send EST CACerts Request
    [Documentation]    Perform the RFC 7030 Section 4.1 /cacerts retrieval (HTTP GET) and return
    ...                the requests response object. Requires a reachable EST server.
    ${url}=    Build EST URL    cacerts
    ${resp}=    GET    ${url}    expected_status=any    verify=${EST_VERIFY_TLS}
    RETURN    ${resp}

Send EST Simple Enroll Request
    [Documentation]    Perform the RFC 7030 Section 4.2.1 /simpleenroll request (HTTP POST of a
    ...                base64 PKCS#10 body) and return the requests response object.
    [Arguments]    ${csr_der}
    ${url}=    Build EST URL    simpleenroll
    ${body}=    Build EST Enroll Request Body    ${csr_der}
    &{headers}=    Create Dictionary
    ...    Content-Type=application/pkcs10    Content-Transfer-Encoding=base64
    ${resp}=    POST    ${url}    data=${body}    headers=${headers}
    ...    expected_status=any    verify=${EST_VERIFY_TLS}
    RETURN    ${resp}
