# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
#

*** Settings ***
Documentation   Test cases for remote attestation nonce handling by the mock CA,
...             based on draft-ietf-lamps-attestation-freshness-05.

Resource            ../resources/keywords.resource
Resource            ../config/${environment}.robot
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/general_msg_utils.py
Library             ../resources/remote_attestation_utils.py

Test Tags     nonce-freshness    remote-attestation


*** Variables ***
${NONCE_LENGTH_2_SHORT}    31  # Example length that is too short
${NONCE_LENGTH_2_LONG}    311  # Example length that is too long
${NONCE_VALID_TIME}    64   # Example valid nonce time in seconds
${MIN_NONCE_LENGTH}    32   # Minimum nonce length in bytes (256 bits)
${VALID_NONCE_LENGTH}    64  # Valid nonce length in bytes (512 bits)


*** Keywords ***
Build And Send Nonce Request
    [Documentation]    Build a nonce request general message, protect it, and send it to the CA.
    ...                Returns the general response message.
    [Arguments]    ${nonce_requests}
    ${genm}=    Build CMP General Message
    ...    info_values=${nonce_requests}
    ...    recipient=${RECIPIENT}
    ...    sender=${SENDER}
    ${protected_genm}=    Default Protect PKIMessage    ${genm}
    ${genp}=    Exchange PKIMessage    ${protected_genm}
    RETURN    ${genp}

Validate Nonce Response
    [Documentation]    Validate that the general response contains a valid nonce response.
    [Arguments]    ${genp}    ${expected_count}=1
    PKIMessage Body Type Must Be    ${genp}    genp
    ${body}=    Get Asn1 Value    ${genp}    body.genp
    ${count}=    Get Length    ${body}
    Should Be Equal As Integers    ${count}    ${expected_count}
    ...    msg=Expected ${expected_count} nonce response(s), got ${count}
    RETURN    ${body}


*** Test Cases ***
CA SHOULD Reject Nonce Too Short
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 6, the nonce value MUST
    ...                contain a random byte sequence with at least 64 bits of entropy. We send a general message
    ...                request with a nonce length that is too short (less than 8 bytes) and expect the CA to
    ...                reject it. The CA SHOULD respond with an error message, indicating that the nonce length is
    ...                invalid with the failInfo `badRequest`.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 6.
    [Tags]    negative    nonce_length
    ${nonce_req}=    Prepare NonceRequest    nonce_length=7
    ${nonce_requests}=    Create List    ${nonce_req}
    ${info_val}=    Prepare Nonce Request InfoTypeAndValue    ${nonce_requests}
    ${genp}=    Build And Send Nonce Request    ${info_val}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest    exclusive=False

CA SHOULD Reject Nonce Too Long
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 6, the CA MAY enforce
    ...                maximum nonce length constraints. We send a general message request with a nonce that is
    ...                excessively long (> 300 bytes) and expect the CA to reject it. The CA SHOULD respond with
    ...                an error message, indicating that the nonce length is invalid with the failInfo `badRequest`.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 6.
    [Tags]    negative    nonce_length    robot:skip-on-failure
    ${nonce_req}=    Prepare NonceRequest    nonce_length=${NONCE_LENGTH_2_LONG}
    ${nonce_requests}=    Create List    ${nonce_req}
    ${info_val}=    Prepare Nonce Request InfoTypeAndValue    ${nonce_requests}
    ${genp}=    Build And Send Nonce Request    ${info_val}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest    exclusive=False

CA MAY Generate On Its Own Nonce When Hint and Type are Absent
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 3, when a NonceRequest
    ...                structure does not contain type or hint, the RA/CA MAY generate a nonce itself and include it
    ...                in the response. We send a general message request without a verifier hint or evidence type
    ...                and expect the CA to generate its own nonce. The CA MAY respond with a valid general response
    ...                message, which includes its generated nonce.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 3.
    [Tags]    positive    robot:skip-on-failure
    ${nonce_req}=    Prepare NonceRequest    nonce_length=${VALID_NONCE_LENGTH}
    ${nonce_requests}=    Create List    ${nonce_req}
    ${info_val}=    Prepare Nonce Request InfoTypeAndValue    ${nonce_requests}
    ${genp}=    Build And Send Nonce Request    ${info_val}
    ${responses}=    Validate Nonce Response    ${genp}    expected_count=1
    # Verify the response contains a nonce
    ${info_value}=    Get From List    ${responses}    0
    ${nonce_resp_der}=    Get Asn1 Value    ${info_value}    infoValue
    ${nonce_resp}=    Decode From Der    ${nonce_resp_der}    asn1_spec=NonceResponseValueASN1
    ${nonce}=    Get Asn1 Value    ${nonce_resp}    0.nonce
    ${nonce_len}=    Get Length    ${nonce}
    Should Be True    ${nonce_len} >= 8    msg=Nonce should be at least 64 bits (8 bytes), got ${nonce_len}

CA MUST Return An Empty OCTET STRING Nonce When No Verifier Is Reached
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 3, if a CA/RA is not able to
    ...                provide a requested nonce (e.g., due to a failure in reaching the verifier), it MUST respond
    ...                with an empty OCTET STRING nonce. We send a request with an unknown verifier hint and expect
    ...                the CA to respond with an empty nonce and may include additional info inside the PKIHeader to
    ...                indicate the reason for the failure.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 3.
    [Tags]    negative
    ${nonce_req}=    Prepare NonceRequest
    ...    nonce_length=${VALID_NONCE_LENGTH}
    ...    hint=unknown-verifier-xyz-123
    ${nonce_requests}=    Create List    ${nonce_req}
    ${info_val}=    Prepare Nonce Request InfoTypeAndValue    ${nonce_requests}
    ${genp}=    Build And Send Nonce Request    ${info_val}
    ${responses}=    Validate Nonce Response    ${genp}    expected_count=1
    # Verify the response contains an empty nonce
    ${info_value}=    Get From List    ${responses}    0
    ${nonce_resp_der}=    Get Asn1 Value    ${info_value}    infoValue
    ${nonce_resp}=    Decode From Der    ${nonce_resp_der}    asn1_spec=NonceResponseValueASN1
    ${nonce}=    Get Asn1 Value    ${nonce_resp}    0.nonce
    ${nonce_len}=    Get Length    ${nonce}
    Should Be Equal As Integers    ${nonce_len}    0
    ...    msg=Expected empty nonce when verifier is unreachable, got ${nonce_len} bytes

CA MUST Return Correct Order Of NonceResponses
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 3, the order in which the
    ...                NonceRequest structures were sent in the request message MUST match the order of the
    ...                NonceResponse structures in the response message. We send multiple nonce requests and expect
    ...                the CA to return the nonce responses in the correct order, with each containing the correct
    ...                nonce corresponding to the respective request.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 3.
    [Tags]    positive    nonce-order
    ${nonce_req1}=    Prepare NonceRequest    nonce_length=32    hint=verifier1
    ${nonce_req2}=    Prepare NonceRequest    nonce_length=48    hint=verifier2
    ${nonce_req3}=    Prepare NonceRequest    nonce_length=64    hint=verifier3
    ${nonce_req_list}=    Create List    ${nonce_req1}    ${nonce_req2}    ${nonce_req3}
    ${info_val}=    Prepare Nonce Request InfoTypeAndValue    ${nonce_req_list}
    ${genp}=    Build And Send Nonce Request    ${info_val}
    ${responses}=    Validate Nonce Response    ${genp}    expected_count=1
    # Verify the response contains three nonce responses in correct order
    ${info_value}=    Get From List    ${responses}    0
    ${nonce_resp_der}=    Get Asn1 Value    ${info_value}    infoValue
    ${nonce_resp_seq}=    Decode From Der    ${nonce_resp_der}    asn1_spec=NonceResponseValueASN1
    ${resp_count}=    Get Length    ${nonce_resp_seq}
    Should Be Equal As Integers    ${resp_count}    3    msg=Expected 3 nonce responses, got ${resp_count}

CA SHOULD Detect Mismatched Nonce In CSR
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 6, the CA/RA MUST validate
    ...                that the nonce provided in the Evidence matches the one previously sent. We first request a
    ...                nonce, then send a CSR with attestation evidence containing a different nonce. The CA SHOULD
    ...                detect the mismatch and respond with an error message, indicating that the nonce does not
    ...                match with the failInfo `badRequest`.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 6.
    [Tags]    negative    robot:skip-on-failure
    # This test requires full attestation evidence processing which is not yet implemented
    Skip    This test requires attestation evidence processing not yet implemented in MockCA

CA COULD Accept NonceRequest Without Type And Use For All Evidences
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 3, if a nonce is provided in a
    ...                NonceResponse structure without indicating any type or hint, it can be used for all Evidence
    ...                statements requiring a nonce. We send a nonce request that does not specify an evidence type
    ...                and expect the CA to accept it. The CA COULD allow the usage of the same nonce for all
...                evidences in subsequent CSR containing multiple evidences of different types.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 3.
    [Tags]    positive    robot:skip-on-failure
    # This test requires full attestation evidence processing which is not yet implemented
    Skip    This test requires attestation evidence processing not yet implemented in MockCA

CA MUST Reject A Expired Nonce
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 3, an Evidence statement
    ...                generated using a nonce provided with an expiry value will be accepted by the Verifier as
    ...                valid until the respective expiry time has elapsed. We first request a nonce with a short
    ...                expiry time, wait for it to expire, then attempt to use it in a CSR. The CA MUST reject
    ...                the request and respond with an error message, indicating that the nonce has expired with the
    ...                failInfo `badRequest`.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 3.
    [Tags]    negative    nonce-expiry    robot:skip-on-failure
    # This test requires attestation evidence processing and time-based validation
    Skip    This test requires attestation evidence and time-based validation not yet implemented in MockCA

CA MUST Return a At Least 64 Bits of Entropy Nonce
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 sections 6 and 8, the nonce value
    ...                MUST contain a random byte sequence with at least 64 bits of entropy. We send a general
    ...                message request without specifying a nonce length and expect the CA to return a nonce of at
    ...                least 64 bits (8 bytes). The CA MUST respond with a valid general response message, which
    ...                includes a nonce that is at least 8 bytes long.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Sections 6 and 8.
    [Tags]    positive    nonce_length    entropy
    ${nonce_req}=    Prepare NonceRequest
    ${nonce_requests}=    Create List    ${nonce_req}
    ${info_val}=    Prepare Nonce Request InfoTypeAndValue    ${nonce_requests}
    ${genp}=    Build And Send Nonce Request    ${info_val}
    ${responses}=    Validate Nonce Response    ${genp}    expected_count=1
    # Verify the response contains a nonce with at least 64 bits (8 bytes)
    ${info_value}=    Get From List    ${responses}    0
    ${nonce_resp_der}=    Get Asn1 Value    ${info_value}    infoValue
    ${nonce_resp}=    Decode From Der    ${nonce_resp_der}    asn1_spec=NonceResponseValueASN1
    ${nonce}=    Get Asn1 Value    ${nonce_resp}    0.nonce
    ${nonce_len}=    Get Length    ${nonce}
    Should Be True    ${nonce_len} >= 8
    ...    msg=Nonce must be at least 64 bits (8 bytes) for entropy, got ${nonce_len} bytes

CA MUST Detect a Reused Nonce
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 6, the RA/CA MUST ensure that
    ...                nonces are unique and MUST NOT be reused. We send two general message requests with a hint
    ...                for a verifier which returns the same nonce both times and expect the CA to detect the reuse.
    ...                The CA MUST respond with an empty OCTET STRING nonce for the second request and may include
    ...                an appropriate error information in the PKIHeader to indicate the reason for the failure.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 6.
    [Tags]    negative    nonce-reuse    robot:skip-on-failure
    # This test requires the MockCA to track previously issued nonces
    Skip    This test requires nonce reuse detection not yet fully implemented in MockCA

CA MAY Know The Allowed PSA Nonce Sizes
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 6, the PSA attestation token
    ...                supports nonce lengths of 32, 48, and 64 bytes. The CA MAY have knowledge of the allowed
    ...                nonce sizes for different PSA verifiers. We send a general message request with nonce
    ...                requests indicating the PSA attestation type and a specified length of 31 (invalid for PSA).
    ...                We expect the CA to reject the request with an error message, indicating that the nonce
    ...                length is invalid for the PSA attestation type.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 6; RFC 9783.
    [Tags]    negative    nonce_length    psa_verifiers    robot:skip-on-failure
    ${nonce_req}=    Prepare NonceRequest
    ...    nonce_length=31
    ...    evidence_type=${id_psa_attestation_token_evidence}
    ${nonce_requests}=    Create List    ${nonce_req}
    ${info_val}=    Prepare Nonce Request InfoTypeAndValue    ${nonce_requests}
    ${genp}=    Build And Send Nonce Request    ${info_val}
    PKIMessage Body Type Must Be    ${genp}    error
    PKIStatus Must Be    ${genp}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${genp}    failinfo=badRequest    exclusive=False

CA Test Nonce Size For All Verifiers
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 8, we send general message
    ...                requests with nonce requests for different verifier types and expect the CA to return nonces
    ...                of appropriate lengths for each verifier type. The CA MUST respond with valid general
    ...                response messages, each containing a nonce that meets the length requirements for the
    ...                respective verifier type.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 8.
    [Tags]    positive    nonce_length    entropy    robot:skip-on-failure
    # Test with PSA verifier expecting 32, 48, or 64 byte nonces
    ${nonce_req1}=    Prepare NonceRequest    nonce_length=32
    ${nonce_req2}=    Prepare NonceRequest    nonce_length=48
    ${nonce_req3}=    Prepare NonceRequest    nonce_length=64
    ${nonce_req_list}=    Create List    ${nonce_req1}    ${nonce_req2}    ${nonce_req3}
    ${info_val}=    Prepare Nonce Request InfoTypeAndValue    ${nonce_req_list}
    ${genp}=    Build And Send Nonce Request    ${info_val}
    ${responses}=    Validate Nonce Response    ${genp}    expected_count=1
    # Verify the response contains three nonce responses with correct lengths
    ${info_value}=    Get From List    ${responses}    0
    ${nonce_resp_der}=    Get Asn1 Value    ${info_value}    infoValue
    ${nonce_resp_seq}=    Decode From Der    ${nonce_resp_der}    asn1_spec=NonceResponseValueASN1
    ${nonce1}=    Get Asn1 Value    ${nonce_resp_seq}    0.nonce
    ${nonce2}=    Get Asn1 Value    ${nonce_resp_seq}    1.nonce
    ${nonce3}=    Get Asn1 Value    ${nonce_resp_seq}    2.nonce
    ${len1}=    Get Length    ${nonce1}
    ${len2}=    Get Length    ${nonce2}
    ${len3}=    Get Length    ${nonce3}
    Should Be Equal As Integers    ${len1}    32    msg=First nonce should be 32 bytes
    Should Be Equal As Integers    ${len2}    48    msg=Second nonce should be 48 bytes
    Should Be Equal As Integers    ${len3}    64    msg=Third nonce should be 64 bytes

CA MUST Return a Nonce With Sufficient Entropy
    [Documentation]    According to draft-ietf-lamps-attestation-freshness-05 section 8, the nonce MUST have at
    ...                least 64 bits of entropy and should be derived using a salt from a genuinely random number
    ...                generator. We send a general message request for a nonce and expect the CA to return a nonce
    ...                with sufficient entropy. The CA MUST respond with a valid general response message, which
    ...                includes a nonce that is generated using a secure random number generator and has sufficient
    ...                entropy to prevent predictability.
    ...                Ref: draft-ietf-lamps-attestation-freshness-05, Section 8.
    [Tags]    positive    nonce_entropy    entropy    robot:skip-on-failure
    Skip    This test should set a number of requests to the CA and analyze the returned nonces for
    ...    randomness and entropy, which is not implemented yet.
