# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Minimal CMP tests.
Library             Collections
Library             OperatingSystem
Library             Process
Library             String
Library             cmp_client.py

Suite Setup         Ensure Environment Clean
Test Setup          Ensure Environment Clean


*** Variables ***
${CMP_URL}          http://127.0.0.1:5000/issuing
${CMP_KEY}          ${CURDIR}${/}certs${/}client_key.pem
${CMP_SECRET}       pass:SiemensIT
${CMP_MAC}          hmac-sha1
${CMP_RECIPIENT}    /CN=Mock CA
${CERT_OUT}         ${CURDIR}${/}certs${/}received_cert.pem

# CMP Commands - Adapt these for your cmp client, default is OpenSSL
# CMP_CLIENT variable is always called first in the cli command
${CMP_CLIENT}    openssl
${INITIATION_REQUEST}      ir
${CERTIFICATION_REQUEST}   p10cr
${KEY_UPDATE_REQUEST}      kur
${REVOCATION_REQUEST}      rr

# Location of the client under test when using gencmpclient
# (defaults assume a sibling checkout of https://github.com/siemens/gencmpclient,
# built with `make -f Makefile_v1 build USE_LIBCMP=1`; override on the command line
# via --variable CMP_CLIENT_BIN:/path/to/cmpClient etc. if needed)
${CMP_CLIENT_BIN}    ${CURDIR}${/}..${/}..${/}gencmpclient${/}cmpClient
${CMP_CLIENT_LIB}    ${CURDIR}${/}..${/}..${/}gencmpclient


*** Test Cases ***
# === IR Tests ===
IR 01 - Valid IR CMP Request Should Pass
    [Documentation]    Send a new certificate initialization request using a CMP client with MAC-based protection.
    ...
    ...                This test simulates a new certificate enrollment by generating a new key and
    ...                sending an Initialization Request (IR). The request includes:
    ...                - a subject (`/CN=IR-Client-1`) matching the senderKID
    ...                - a correct shared secret for HMAC protection
    ...                - a recipient name matching the CA subject
    ...
    ...                The client output should not contain any errors,
    ...                and a certificate should be written to the specified path.
    [Tags]    ir    valid    positive
    ${output}=    Run CMP Client
    ...    cmd=${INITIATION_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=IR-Client-1
    ...    subject=/CN=IR-Client-1
    ...    secret=${CMP_SECRET}
    ...    recipient=${CMP_RECIPIENT}
    ...    newkey=${CMP_KEY}
    ...    certout=${CERT_OUT}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Not Contain Any    ${out}    error
    Should Be Equal As Integers    ${output.rc}    0
    File Should Exist    ${CERT_OUT}

IR 02 - IR Request With Wrong Secret Should Fail
    [Documentation]    Send an IR request using a CMP client with an invalid shared secret to test MAC failure handling.
    ...
    ...                This test sends an Initialization Request with a wrong password (`WrongPassword`),
    ...                while keeping all other parameters valid.
    ...
    ...                The client output should indicate a failure due to authentication error
    ...                and include the keyword `error`.
    [Tags]    ir    negative    secret
    ${output}=    Run CMP Client
    ...    cmd=${INITIATION_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=IR-Client-2
    ...    subject=/CN=IR-Client-2
    ...    secret=pass:WrongPassword
    ...    recipient=${CMP_RECIPIENT}
    ...    newkey=${CMP_KEY}
    ...    certout=${CERT_OUT}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Contain Any    ${out}    error
    Should Not Be Equal As Integers    ${output.rc}    0
    File Should Not Exist    ${CERT_OUT}

IR 03 - Valid IR With Implicit Confirm Should Pass
    [Documentation]    Send a valid IR request asking the CA to grant implicit confirmation.
    ...
    ...                Same as IR 01, but with the implicitConfirm extension requested,
    ...                so that no explicit certConf message needs to be exchanged.
    [Tags]    ir    valid    positive    implicit-confirm
    ${output}=    Run CMP Client
    ...    cmd=${INITIATION_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=IR-Client-3
    ...    subject=/CN=IR-Client-3
    ...    secret=${CMP_SECRET}
    ...    recipient=${CMP_RECIPIENT}
    ...    newkey=${CMP_KEY}
    ...    certout=${CERT_OUT}
    ...    implicit_confirm=1
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Not Contain Any    ${out}    error
    Should Be Equal As Integers    ${output.rc}    0
    File Should Exist    ${CERT_OUT}

# === P10CR Tests ===

P10CR 01 - P10CR Unprotected Request Should Fail
    [Documentation]    Send a P10CR request with `-unprotected_requests` to simulate missing protection.
    ...
    ...                This test sends a certificate request without MAC or cert protection.
    ...                It includes a valid CSR but disables protection flags.
    ...
    ...                The client should log an error since the CA rejects the unprotected request.
    [Tags]    p10cr    negative    unprotected
    ${output}=    Run CMP Client
    ...    cmd=${CERTIFICATION_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=P10CR-Client-1
    ...    subject=/CN=P10CR-Client-1
    ...    secret=${CMP_SECRET}
    ...    csr=${CURDIR}${/}certs${/}csr.pem
    ...    unprotected_requests=1
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Not Be Equal As Integers    ${output.rc}    0
    Should Contain    ${out}    error
    Should Contain    ${out}    protection

P10CR 02 - P10CR With Missing CSR Should Fail
    [Documentation]    Send a P10CR request without a CSR using a CMP client to test input validation.
    ...
    ...                This test omits the `csr` option entirely, resulting in a malformed request.
    ...
    ...                The client should output an error message indicating missing or invalid input.
    [Tags]    p10cr    negative    malformed
    ${output}=    Run CMP Client
    ...    cmd=${CERTIFICATION_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=P10CR-Client-2
    ...    subject=/CN=P10CR-Client-2
    ...    secret=${CMP_SECRET}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Not Be Equal As Integers    ${output.rc}    0
    Should Contain    ${out}    missing
    Should Contain    ${out}    error
    Should Contain    ${out}    csr

P10CR 03 - Valid P10CR With CSR Should Pass
    [Documentation]    Send a valid P10CR request using a CSR and MAC-based protection.
    ...
    ...                This test uses a signed CSR (`csr_p10cr-client-3.pem`) and a shared secret
    ...                to authenticate the request. The subject in the CSR matches the subject in the CMP header.
    ...
    ...                Note: this test cannot pass with the plain OpenSSL CMP app, since it does not
    ...                set the senderKID to the sender CN as required by RFC 9483 Section 3.1;
    ...                use gencmpclient built with USE_LIBCMP=1 instead.
    [Tags]    p10cr    positive    validation
    ${output}=    Run CMP Client
    ...    cmd=${CERTIFICATION_REQUEST}
    ...    server=${CMP_URL}
    ...    recipient=${CMP_RECIPIENT}
    ...    subject=/CN=P10CR-Client-3
    ...    secret=${CMP_SECRET}
    ...    csr=${CURDIR}${/}certs${/}csr_p10cr-client-3.pem
    ...    certout=${CERT_OUT}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Not Contain    ${out}    error
    Should Be Equal As Integers    ${output.rc}    0
    File Should Exist    ${CERT_OUT}

P10CR 04 - P10CR With Wrong Secret Should Fail
    [Documentation]    Send a P10CR request with an invalid shared secret to test MAC failure handling.
    ...
    ...                Mirrors IR 02 for the p10cr case: a valid CSR is sent, but the request is
    ...                MAC-protected with a wrong password, so the CA must reject it.
    [Tags]    p10cr    negative    secret
    ${output}=    Run CMP Client
    ...    cmd=${CERTIFICATION_REQUEST}
    ...    server=${CMP_URL}
    ...    recipient=${CMP_RECIPIENT}
    ...    subject=/CN=P10CR-Client-3
    ...    secret=pass:WrongPassword
    ...    csr=${CURDIR}${/}certs${/}csr_p10cr-client-3.pem
    ...    certout=${CERT_OUT}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Contain    ${out}    error
    Should Not Be Equal As Integers    ${output.rc}    0
    File Should Not Exist    ${CERT_OUT}


*** Keywords ***
Ensure Environment Clean
    [Documentation]    Remove leftover output files from previous test runs.
    Remove File    ${CERT_OUT}

Run CMP Client
    [Documentation]    Render the CLI command for ${CMP_CLIENT} and run it, returning the process result.
    [Arguments]    &{kwargs}
    ${args}=    Get CMP Command    ${CMP_CLIENT}    bin=${CMP_CLIENT_BIN}    &{kwargs}
    Log    CMP Request Args: ${args}
    ${output}=    Run Process    @{args}    stderr=STDOUT
    ...    env:LD_LIBRARY_PATH=${CMP_CLIENT_LIB}
    Log    CMP Request Output (rc=${output.rc}): ${output.stdout}
    RETURN    ${output}
