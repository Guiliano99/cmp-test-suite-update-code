# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP logic, not necessarily specific to the lightweight profile

Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../pq_logic/py_verify_logic.py
Library             ../pq_logic/pq_validation_utils.py



Test Tags           pq-sig   pqc

Suite Setup         Initialize Global Variables

*** Keywords ***

Initialize Global Variables
    ${cert}   ${key}=   May Load Cert And Key    data/unittest/ca1_cert_ecdsa.pem   data/keys/private-key-ecdsa.pem
    VAR   ${OTHER_TRUSTED_PKI_CERT}  ${cert}   scope=Global
    VAR   ${OTHER_TRUSTED_PKI_KEY}   ${key}    scope=Global
    ${cert}   ${key}=   May Load Cert And Key    data/unittest/ca1_cert_ecdsa.pem   data/keys/private-key-ecdsa.pem
    VAR   ${ISSUED_CERT}  ${cert}   scope=Global
    VAR   ${ISSUED_KEY}   ${key}    scope=Global

*** Variables ***

${DEFAULT_ML_DSA_KEY}    ml-dsa-65

*** Test Cases ***

############################
# ML-DSA Tests
############################

CA MUST Issue A Valid ML-DSA-44 Cert
    [Documentation]   According to fips204 is the ML-DSA-44 ObjectIdentifier and the algorithm used. We send an IR
    ...               Initialization Request with a valid ML-DSA private key. The CA MUST process the request
    ...               and issue a valid certificate.
    [Tags]   positive  ml-dsa
    ${key}=   Generate Key    ml-dsa-44
    ${cm}=   Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}    ${cm}
    ...    recipient=${RECIPIENT}
    ...    omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Migration Certificate Key Usage   ${cert}

CA MUST Reject A Invalid ML-DSA-44 POP
    [Documentation]   According to fips204 is the ML-DSA-44 ObjectIdentifier and the algorithm used. We send an IR
    ...               Initialization Request with a valid ML-DSA private key, but the POP is invalid. The CA
    ...               MUST reject the request and MAY respond with the optional failInfo `badPOP`.
    [Tags]   negative   pop   ml-dsa
    ${key}=   Generate Key    ml-dsa-44
    ${cm}=   Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}    ${cm}    bad_pop=True
    ...    recipient=${RECIPIENT}
    ...    omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    Verify PKIStatusInfo    ${response}   failinfos=badPOP

CA MUST Accept A Valid KGA Request For ML-DSA
    [Documentation]   We send an Initialization Request indicating the CA to issue a certificate for a ML-DSA Private
    ...               Key, to be generated by the Key Generation Authority (KGA). The CA MUST process the request and
    ...               issue a valid certificate and send a encrypted private key inside the `SignedData` structure.
    [Tags]            ir    positive   kga
    ${key}=   Generate Key    ${DEFAULT_ML_DSA_KEY}
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}
    ...    for_kga=True
    ...    recipient=${RECIPIENT}
    ...    pvno=3
    ...    omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be     ${response}    status=accepted


############################
# SLH-DSA Tests
############################

CA MUST Accept Valid SLH-DSA IR
    [Documentation]   According to fips205 is the SLH-DSA ObjectIdentifier and the algorithm used. We send an IR
    ...               Initialization Request with a valid SLH-DSA private key. The CA MUST process the request
    ...               and issue a valid certificate.
    [Tags]       positive   slh-dsa 
    ${key}=   Generate Key    slh-dsa
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}
    ...       recipient=${RECIPIENT}
    ...       omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be       ${response}    status=accepted
    PKIMessage Body Type Must Be   ${response}    ip
    ${cert}=   Get Cert From PKIMessage    ${response}
    Validate Migration Certificate Key Usage   ${cert}
    
CA MUST Reject SLH-DSA IR with Invalid POP
    [Documentation]   According to fips205 is the SLH-DSA ObjectIdentifier and the algorithm used. We send an IR
    ...               Initialization Request with a valid SLH-DSA private key, but the POP is invalid. The CA
    ...               MUST reject the request and MAY respond with the optional failInfo `badPOP`.
    ${key}=   Generate Key    slh-dsa
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}
    ...       recipient=${RECIPIENT}
    ...       bad_pop=True
    ...       omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    implicit_confirm=${True}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

    
############################
# FN-DSA Tests
############################


############################
## Pre-Hashed Versions
############################

CA MUST Issue a valid ML-DSA-44 with Sha512 Certificate
    [Documentation]   According to fips204 is the ML-DSA ObjectIdentifier and the algorithm used. We send an IR
    ...               Initialization Request with a valid ML-DSA private key. The CA MUST process the request
    ...               and issue a valid certificate.
    [Tags]       positive   ml-dsa
    ${key}=   Generate Key    ml-dsa-44
    ${cm}=    Get Next Common Name
    ${spki}=   Prepare SubjectPublicKeyInfo    ${key}   hash_alg=sha512
    ${cert_req_msg}=    Prepare CertReqMsg    ${key}   common_name=${cm}   hash_alg=sha512   spki=${spki}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   cert_req_msg=${cert_req_msg}
    ...       recipient=${RECIPIENT}
    ...       omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...                 pki_message=${ir}
    ...                 protection=signature
    ...                 private_key=${ISSUED_KEY}
    ...                 cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Validate Migration Oid In Certificate     ${cert}   ml-dsa-44-sha512

CA MUST Issue A Valid ML-DSA-65 With Sha512 Certificate
    [Documentation]   According to fips204 is the ML-DSA ObjectIdentifier and the algorithm used. We send an IR
    ...               Initialization Request with a valid ML-DSA-65 private key. The CA MUST process the request
    ...               and issue a valid certificate.
    [Tags]       positive   ml-dsa
    ${key}=   Generate Key    ml-dsa-65
    ${cm}=    Get Next Common Name
    ${spki}=   Prepare SubjectPublicKeyInfo    ${key}   hash_alg=sha512
    ${cert_req_msg}=    Prepare CertReqMsg    ${key}   common_name=${cm}   hash_alg=sha512   spki=${spki}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   cert_req_msg=${cert_req_msg}
    ...       recipient=${RECIPIENT}
    ...       omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...                 pki_message=${ir}
    ...                 protection=signature
    ...                 private_key=${ISSUED_KEY}
    ...                 cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Validate Migration Oid In Certificate     ${cert}   ml-dsa-65-sha512

CA MUST Issue A Valid ML-DSA-87 With Sha512 Certificate
    [Documentation]   According to fips204 is the ML-DSA ObjectIdentifier and the algorithm used. We send an IR
    ...               Initialization Request with a valid ML-DSA-87 private key. The CA MUST process the request
    ...               and issue a valid certificate.
    [Tags]       positive   ml-dsa
    ${key}=   Generate Key    ml-dsa-87
    ${cm}=    Get Next Common Name
    ${spki}=   Prepare SubjectPublicKeyInfo    ${key}   hash_alg=sha512
    ${cert_req_msg}=    Prepare CertReqMsg    ${key}   common_name=${cm}   hash_alg=sha512   spki=${spki}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   cert_req_msg=${cert_req_msg}
    ...       recipient=${RECIPIENT}
    ...       omit_fields=senderKID,sender
    ${protected_ir}=    Protect PKIMessage
    ...                 pki_message=${ir}
    ...                 protection=signature
    ...                 private_key=${ISSUED_KEY}
    ...                 cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Validate Migration Oid In Certificate     ${cert}   ml-dsa-87-sha512

