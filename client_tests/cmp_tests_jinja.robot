# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Minimal CMP tests.
Library             Process
Library             Collections
Library             OperatingSystem
Library             String
Library             cmp_client.py

Suite Setup         Ensure Environment Clean
Test Setup          Ensure Environment Clean

*** Variables ***
${CMP_URL}          http://127.0.0.1:5000/issuing
${CMP_KEY}          certs/client_key.pem
${CMP_SECRET}       pass:SiemensIT
${CMP_MAC}          hmac-sha1
${CMP_RECIPIENT}    /CN=Mock-CA
${CERT_OUT}         certs/received_cert.pem

# CMP Commands - Adapt these for you cmp client, default is OpenSSL
# CMP_CLIENT variable is always called first in the cli command
${CMP_CLIENT}    openssl
${INITIATION_REQUEST}      ir
${CERTIFICATION_REQUEST}   p10cr
${CR_REQUEST}              cr
${KEY_UPDATE_REQUEST}      kur
${REVOCATION_REQUEST}      rr

# Client capability flags gating the positive KUR/RR tests. They default to False
# because neither the minimal OpenSSL command template nor gencmpclient-rs wire up
# full key-update / revocation enrolment here. A client that supports them opts in:
#     robot --variable CLIENT_SUPPORTS_KUR:True --variable CLIENT_SUPPORTS_RR:True ...
${CLIENT_SUPPORTS_KUR}     ${FALSE}
${CLIENT_SUPPORTS_RR}      ${FALSE}

*** Keywords ***
Ensure Environment Clean
    Remove File    certs/received_cert.pem

*** Test Cases ***

# === IR Tests ===
IR 01 - Valid IR CMP Request Should Pass
    [Documentation]    Send a new certificate initialization request using OpenSSL CMP client with MAC-based protection.
    ...
    ...                This test simulates a new certificate enrollment by generating a new key and
    ...                sending an Initialization Request (IR). The request includes:
    ...                - a subject (`/CN=IR-Client-1`) matching the senderKID
    ...                - a correct shared secret for HMAC protection
    ...                - a recipient name matching the CA subject
    ...
    ...                The OpenSSL client output should not contain any errors,
    ...                and a certificate should be written to the specified path.
    [Tags]    ir    valid    positive

    ${args}=    Get CMP Command
    ...    ${CMP_CLIENT}
    ...    cmd=${INITIATION_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=IR-Client-1
    ...    subject=/CN=IR-Client-1
    ...    secret=${CMP_SECRET}
    ...    recipient=${CMP_RECIPIENT}
    ...    newkey=${CMP_KEY}
    ...    certout=${CERT_OUT}   
    log    CMP Request Args: ${args}
    Run Process    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run 
    ${output}=    Wait For Process    cmp_run
    LOG    CMP Request Output: ${output.stdout}
    LOG    CMP Request rc: ${Output.rc}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Not Contain Any    ${out}    error
    Should Be Equal As Integers  ${output.rc}    0  
    File Should Exist     ${CERT_OUT}

IR 02 - IR Request With Wrong Secret Should Fail

    [Documentation]    Send an IR request using OpenSSL CMP client with an invalid shared secret to test MAC failure handling.
    ...
    ...                This test sends an Initialization Request with a wrong password (`WrongPassword`),
    ...                while keeping all other parameters valid.
    ...
    ...                The OpenSSL client output should indicate a failure due to authentication error
    ...                and include the keyword `error`.
    [Tags]    ir    negative    secret
    ${args}=    Get CMP Command
    ...    ${CMP_CLIENT}
    ...    cmd=${INITIATION_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=IR-Client-2
    ...    subject=/CN=IR-Client-2
    ...    secret=pass:WrongPassword
    ...    recipient=${CMP_RECIPIENT}
    ...    newkey=${CMP_KEY}
    ...    certout=${CERT_OUT}   
    log    CMP Request Args: ${args}
    Run Process    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run 
    ${output}=    Wait For Process    cmp_run
    LOG    CMP Request Output: ${output.stdout}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Contain Any    ${out}    error
    Should Not Be Equal As Integers  ${output.rc}    0
    File Should Not Exist     ${CERT_OUT}

# === P10CR Tests ===
P10CR 01 - P10CR Unprotected Request Should Fail
    [Documentation]    Send a P10CR request with `-unprotected_requests` using OpenSSL to simulate missing protection.
    ...
    ...                This test sends a certificate request without MAC or cert protection.
    ...                It includes a valid CSR but disables protection flags.
    ...
    ...                The OpenSSL client should log an error related to missing request protection.
    [Tags]    p10cr    negative    unprotected
    ${args}=    Get CMP Command
    ...    ${CMP_CLIENT}
    ...    cmd=${CERTIFICATION_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=P10CR-Client-1
    ...    subject=/CN=P10CR-Client-1
    ...    secret=${CMP_SECRET}
    ...    csr=certs/csr.pem
    ...    unprotected_requests=1

    Run Process    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run
    ${output}=    Wait For Process    cmp_run
    LOG    CMP Request Output: ${output.stdout}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Not Be Equal As Integers  ${output.rc}    0
    Should Contain    ${out}    error
    Should Contain    ${out}    protection    


P10CR 02 - P10CR With Missing CSR Should Fail
    
    [Documentation]    Send a P10CR request without a CSR using a CMP client to test input validation.
    ...
    ...                This test omits the `csr` option entirely, resulting in a malformed request.
    ...
    ...                The client should output an error message indicating missing or invalid input.
    [Tags]    p10cr    negative    malformed
    ${args}=    Get CMP Command
    ...    ${CMP_CLIENT}
    ...    cmd=${CERTIFICATION_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=P10CR-Client-2
    ...    subject=/CN=P10CR-Client-2
    ...    secret=${CMP_SECRET}
    
    Run Process    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run
    ${output}=    Wait For Process    cmp_run
    LOG    CMP Request Output: ${output.stdout}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Not Be Equal As Integers  ${output.rc}    0
    Should Contain    ${out}    missing
    Should Contain    ${out}    error
    Should Contain    ${out}    csr

P10CR 03 - Valid P10CR With CSR Should Pass
    [Documentation]    Send a valid P10CR request using a CSR and MAC-based protection with OpenSSL CMP client.
    ...
    ...                This test uses a signed CSR (`csr_p10cr-client-3.pem`) and a shared secret
    ...                to authenticate the request. The subject in the CSR matches the subject in the CMP header.
    [Tags]    p10cr    positive    validation
    ${args}=    Get CMP Command
    ...    ${CMP_CLIENT}
    ...    cmd=${CERTIFICATION_REQUEST}
    ...    server=${CMP_URL}
    ...    recipient=${CMP_RECIPIENT}
    ...    subject=/CN=P10CR-Client-3
    ...    secret=${CMP_SECRET}
    ...    csr=certs/csr_p10cr-client-3.pem
    ...    certout=${CERT_OUT}
    Run Process    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run
    ${output}=    Wait For Process    cmp_run
    LOG    CMP Request Output: ${output.stdout}
    Should Be Equal As Integers  ${output.rc}    0
    Should Not Contain    ${output.stdout.lower()}    error

# === Additional IR Test ===
IR 03 - Issued Certificate Is A Parseable Certificate
    [Documentation]    According to RFC 9483 Section 4.1.1, a successful Initialization Request must yield a
    ...                certificate. Beyond checking the exit code, this test verifies that the client actually
    ...                wrote a well-formed PEM certificate to the requested output path, guarding against a
    ...                client that returns success but produces no usable certificate.
    [Tags]    ir    valid    positive
    ${args}=    Get CMP Command
    ...    ${CMP_CLIENT}
    ...    cmd=${INITIATION_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=IR-Client-3
    ...    subject=/CN=IR-Client-3
    ...    secret=${CMP_SECRET}
    ...    recipient=${CMP_RECIPIENT}
    ...    newkey=${CMP_KEY}
    ...    certout=${CERT_OUT}
    Run Process    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run
    ${output}=    Wait For Process    cmp_run
    LOG    CMP Request Output: ${output.stdout}
    Should Be Equal As Integers    ${output.rc}    0
    File Should Exist    ${CERT_OUT}
    ${cert}=    Get File    ${CERT_OUT}
    Should Contain    ${cert}    BEGIN CERTIFICATE
    Should Contain    ${cert}    END CERTIFICATE

# === CR Tests ===
CR 01 - Valid CR CMP Request Should Pass
    [Documentation]    According to RFC 9483 Section 4.1.2, a Certification Request (CR) enrols a new certificate
    ...                for a freshly generated key, just like an IR but for an already-initialised end entity.
    ...                This test sends a MAC-protected CR and expects a certificate to be issued.
    [Tags]    cr    valid    positive
    ${args}=    Get CMP Command
    ...    ${CMP_CLIENT}
    ...    cmd=${CR_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=CR-Client-1
    ...    subject=/CN=CR-Client-1
    ...    secret=${CMP_SECRET}
    ...    recipient=${CMP_RECIPIENT}
    ...    newkey=${CMP_KEY}
    ...    certout=${CERT_OUT}
    Run Process    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run
    ${output}=    Wait For Process    cmp_run
    LOG    CMP Request Output: ${output.stdout}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Not Contain Any    ${out}    error
    Should Be Equal As Integers    ${output.rc}    0
    File Should Exist    ${CERT_OUT}

# === KUR Tests ===
KUR 01 - Valid Key Update Request Should Pass
    [Documentation]    According to RFC 9483 Section 4.1.3, a Key Update Request (KUR) updates an existing
    ...                certificate. This positive test is only executed for clients that advertise KUR support
    ...                via ${CLIENT_SUPPORTS_KUR}; clients that stub KUR (e.g. gencmpclient-rs) skip it.
    [Tags]    kur    positive
    Skip If    not ${CLIENT_SUPPORTS_KUR}    Client does not support kur (set CLIENT_SUPPORTS_KUR to enable)
    ${args}=    Get CMP Command
    ...    ${CMP_CLIENT}
    ...    cmd=${KEY_UPDATE_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=IR-Client-1
    ...    subject=/CN=IR-Client-1
    ...    secret=${CMP_SECRET}
    ...    recipient=${CMP_RECIPIENT}
    ...    newkey=${CMP_KEY}
    ...    certout=${CERT_OUT}
    Run Process    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run
    ${output}=    Wait For Process    cmp_run
    LOG    CMP Request Output: ${output.stdout}
    Should Be Equal As Integers    ${output.rc}    0
    File Should Exist    ${CERT_OUT}

KUR 02 - Key Update Request With No Inputs Should Fail
    [Documentation]    A KUR sent without a subject, secret or certificate to update is malformed and the client
    ...                MUST reject it rather than emitting a request. This negative test applies to every client:
    ...                a full client fails validation, a client that stubs KUR reports it is unimplemented.
    [Tags]    kur    negative
    ${args}=    Get CMP Command
    ...    ${CMP_CLIENT}
    ...    cmd=${KEY_UPDATE_REQUEST}
    ...    server=${CMP_URL}
    Run Process    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run
    ${output}=    Wait For Process    cmp_run
    LOG    CMP Request Output: ${output.stdout}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Not Be Equal As Integers    ${output.rc}    0
    Should Contain    ${out}    error

# === RR Tests ===
RR 01 - Valid Revocation Request Should Pass
    [Documentation]    According to RFC 9483 Section 4.2, a Revocation Request (RR) revokes a certificate.
    ...                This positive test is only executed for clients that advertise RR support via
    ...                ${CLIENT_SUPPORTS_RR}; clients that stub RR (e.g. gencmpclient-rs) skip it.
    [Tags]    rr    positive
    Skip If    not ${CLIENT_SUPPORTS_RR}    Client does not support rr (set CLIENT_SUPPORTS_RR to enable)
    ${args}=    Get CMP Command
    ...    ${CMP_CLIENT}
    ...    cmd=${REVOCATION_REQUEST}
    ...    server=${CMP_URL}
    ...    ref=IR-Client-1
    ...    subject=/CN=IR-Client-1
    ...    secret=${CMP_SECRET}
    ...    recipient=${CMP_RECIPIENT}
    Run Process    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run
    ${output}=    Wait For Process    cmp_run
    LOG    CMP Request Output: ${output.stdout}
    Should Be Equal As Integers    ${output.rc}    0

RR 02 - Revocation Request With No Inputs Should Fail
    [Documentation]    An RR sent without a certificate, subject or secret is malformed and the client MUST reject
    ...                it. This negative test applies to every client: a full client fails validation, a client
    ...                that stubs RR reports it is unimplemented.
    [Tags]    rr    negative
    ${args}=    Get CMP Command
    ...    ${CMP_CLIENT}
    ...    cmd=${REVOCATION_REQUEST}
    ...    server=${CMP_URL}
    Run Process    @{args}    stdout=PIPE    stderr=STDOUT    alias=cmp_run
    ${output}=    Wait For Process    cmp_run
    LOG    CMP Request Output: ${output.stdout}
    ${out}=    Convert To Lowercase    ${output.stdout}
    Should Not Be Equal As Integers    ${output.rc}    0
    Should Contain    ${out}    error
