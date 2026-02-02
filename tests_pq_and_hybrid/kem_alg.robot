# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
# robocop: off=ORD03
# ORD03:  Invalid Settings order (should be): Settings > Variables > Test Cases / Tasks > Keywords.


*** Settings ***
Documentation    Tests for PQ KEM algorithms and Hybrid KEM algorithms to verify all known combinations.

Resource            ../resources/keywords.resource
Resource            ../resources/setup_keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../pq_logic/hybrid_issuing.py
Library             ../pq_logic/hybrid_prepare.py
Library             ../pq_logic/pq_verify_logic.py

Test Tags           pqc  verbose-alg   verbose-tests   verbose-kem-tests

Suite Setup         Set Up PQ KEM Suite


*** Comments ***
# TODO: Decide whether to add `cr` request as well.


*** Keywords ***
Request With PQ KEM Key
    [Documentation]  Send a valid Initialization Request for a PQ KEM key.
    [Arguments]    ${alg_name}     ${invalid_key_size}   ${extensions}=${None}    ${add_params_rand}=${False}
    ${response}    ${key}=   Build And Exchange KEM Certificate Request    ${alg_name}    ${invalid_key_size}
    ...          ${extensions}    ${add_params_rand}
    IF   ${invalid_key_size}
        PKIStatus Must Be   ${response}   rejection
        PKIStatusInfo Failinfo Bit Must Be  ${response}  badCertTemplate,badDataFormat  exclusive=False
    ELSE
        PKIStatus Must Be  ${response}   accepted
        ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
        Certificate Must Be Valid    ${cert}
    END

Test All Variants For Algorithm Family
    [Documentation]    Helper keyword to test all variants of an algorithm family.
    ...                This keyword fetches all supported algorithms for the given family
    ...                and tests each variant with the specified validity.
    ...
    ...                Note: Logs each algorithm being tested for better error traceability.
    [Arguments]    ${algorithm_family}    ${invalid_key_size}
    ${algs}=    Get Supported Algorithms By Type    ${algorithm_family}
    FOR    ${algorithm}    IN    @{algs}
        Log    Testing algorithm variant: ${algorithm} (invalid_key_size=${invalid_key_size})    level=INFO
        TRY
            Request With PQ KEM Key    ${algorithm}    ${invalid_key_size}
        EXCEPT    AS    ${error}
            Log    FAILED for algorithm ${algorithm}: ${error}    level=ERROR
            Fail    Algorithm ${algorithm} failed: ${error}
        END
    END

Build And Exchange KEM Certificate Request
    [Documentation]    Build a KEM certificate request and exchange it with the CA to get a certificate.
    ...
    ...                Only builds the Initialization Request for the encrypted cert mechanism request.
    ...
    ...                Arguments:
    ...                - ${key_alg}: The key algorithm to use for the key generation (e.g. `ml-kem-768`).
    ...                - ${invalid_key_size}: Whether to use an invalid key size. Defaults to `False`.
    ...
    ...                Returns:
    ...                - The response from the CA.
    ...                - The key used for the certificate generation.
    ...
    ...                Examples:
    ...                | ${response}= | Build and Exchange KEM Certificate Request | ml-kem-768 |
    ...                | ${response}= | Build and Exchange KEM Certificate Request | ml-kem-768 | False |
    [Arguments]    ${key_alg}    ${invalid_key_size}=False   ${extensions}=${None}   ${add_params_rand}=${False}
    ${key}=    Generate Key    ${key_alg}   by_name=True
    ${cm}=    Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}      invalid_key_size=${invalid_key_size}
    ...         add_params_rand_bytes=${add_params_rand}
    ${cert_req_msg}=    Prepare CertReqMsg  ${key}  spki=${spki}   common_name=${cm}   extensions=${extensions}
    ${ir}=    Build Ir From Key    ${key}   cert_req_msg=${cert_req_msg}   exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}    ${PQ_ISSUING_SUFFIX}
    RETURN    ${response}   ${key}


*** Test Cases ***
ML-KEM Valid Requests - All Variants
    [Documentation]    Test all ML-KEM variants for valid `IR` requests.
    ...
    ...                According to FIPS 203 (ML-KEM specification), all security levels should be tested:
    ...                - ML-KEM-512 (NIST Security Level 1)
    ...                - ML-KEM-768 (NIST Security Level 3)
    ...                - ML-KEM-1024 (NIST Security Level 5)
    [Tags]    positive  pq-kem  ml-kem
    [Template]    Test All Variants For Algorithm Family
    ml-kem    ${False}

ML-KEM Invalid Key Sizes - All Variants
    [Documentation]    Test all ML-KEM variants for invalid key size handling.
    ...
    ...                This test verifies that the CA properly rejects requests with invalid key sizes
    ...                for all ML-KEM algorithm variants.
    [Tags]    negative  pq-kem  ml-kem
    [Template]    Test All Variants For Algorithm Family
    ml-kem    ${True}

