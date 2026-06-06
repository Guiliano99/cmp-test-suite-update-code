# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       In-depth test suite for the Enrollment over Secure Transport (EST) protocol,
...                 RFC 7030 (with RFC 8951 / RFC 8295 / RFC 7894 clarifications and extensions).
...
...                 Tests are split into two groups by tag:
...                 - `est-offline`: message-level checks (URL layout, transfer encoding,
...                   content types, CMS certs-only parsing). They run without a server and are
...                   safe for CI.
...                 - `est-server`: end-to-end checks that talk to a live EST server configured
...                   via ${EST_BASE_URL}. Exclude them with `--exclude est-server` when no
...                   server is available.

Resource            est_keywords.resource

Force Tags          est


*** Test Cases ***
# ---------------------------------------------------------------------------
# RFC 7030 Section 3.2.2 - Well-known URI and operation paths
# ---------------------------------------------------------------------------
EST Endpoint URLs Must Follow The Well-Known Layout
    [Documentation]    RFC 7030 Section 3.2.2: every EST operation lives under the
    ...    "/.well-known/est" path prefix, optionally below an arbitrary label segment.
    [Tags]    est-offline    rfc7030-3.2.2
    ${cacerts}=    Get EST Endpoint URL    https://ca.example    cacerts
    Should Be Equal    ${cacerts}    https://ca.example/.well-known/est/cacerts
    ${enroll}=    Get EST Endpoint URL    https://ca.example    simpleenroll
    Should Be Equal    ${enroll}    https://ca.example/.well-known/est/simpleenroll

EST Endpoint URLs Must Support An Optional Label
    [Documentation]    RFC 7030 Section 3.2.2: an OPTIONAL label may select a CA or enrollment
    ...    profile and is inserted between the prefix and the operation.
    [Tags]    est-offline    rfc7030-3.2.2
    ${url}=    Get EST Endpoint URL    https://ca.example/    simplereenroll    label=RSA-Profile
    Should Be Equal    ${url}    https://ca.example/.well-known/est/RSA-Profile/simplereenroll

EST Endpoint Builder Must Reject Unknown Operations
    [Documentation]    Only the operations defined in RFC 7030 Section 3.2.2 are valid path
    ...    components; anything else must be rejected rather than silently constructed.
    [Tags]    est-offline    rfc7030-3.2.2
    Run Keyword And Expect Error    *Unknown EST operation*
    ...    Get EST Endpoint URL    https://ca.example    notanoperation

# ---------------------------------------------------------------------------
# RFC 7030 Section 3.2.4 / Section 4 - Media types
# ---------------------------------------------------------------------------
EST Operations Must Advertise The Correct Media Types
    [Documentation]    RFC 7030 Section 3.2.4 and Section 4 define the request/response media
    ...    types per operation (e.g. application/pkcs10 in, application/pkcs7-mime out).
    [Tags]    est-offline    rfc7030-3.2.4
    ${req}    ${resp}=    Get EST Content Types    simpleenroll
    Should Be Equal    ${req}    application/pkcs10
    Should Be Equal    ${resp}    application/pkcs7-mime
    ${creq}    ${cresp}=    Get EST Content Types    cacerts
    Should Be Equal    ${creq}    ${None}
    Should Be Equal    ${cresp}    application/pkcs7-mime
    ${kreq}    ${kresp}=    Get EST Content Types    serverkeygen
    Should Be Equal    ${kresp}    multipart/mixed

Content Type Comparison Must Ignore Parameters
    [Documentation]    RFC 7030 responses may carry media-type parameters such as
    ...    "; smime-type=certs-only"; matching must consider only the bare media type.
    [Tags]    est-offline    rfc7030-3.2.4
    ${ok}=    EST Content Type Matches    application/pkcs7-mime; smime-type=certs-only
    ...    application/pkcs7-mime
    Should Be True    ${ok}
    ${bad}=    EST Content Type Matches    text/plain    application/pkcs7-mime
    Should Not Be True    ${bad}

# ---------------------------------------------------------------------------
# RFC 7030 Section 3.2 / RFC 8951 - Transfer encoding
# ---------------------------------------------------------------------------
EST Bodies Must Round-Trip Through Base64 Transfer Encoding
    [Documentation]    RFC 7030 Section 3.2 / RFC 8951: EST payloads are base64-encoded for
    ...    transport. Encoding then decoding must reproduce the original DER exactly.
    [Tags]    est-offline    rfc8951
    ${csr_b64}=    Load EST Test Vector    ${EST_CSR_VECTOR}
    ${der}=    Decode EST Message Body    ${csr_b64}
    ${reencoded}=    Encode EST Message Body    ${der}
    ${der_again}=    Decode EST Message Body    ${reencoded}
    Should Be Equal    ${der}    ${der_again}

Decoder Must Tolerate Line-Wrapped Base64 Bodies
    [Documentation]    RFC 8951: base64 bodies are commonly line-wrapped under
    ...    Content-Transfer-Encoding: base64. Decoding must ignore the inserted newlines.
    [Tags]    est-offline    rfc8951
    ${wrapped}=    Load EST Test Vector    ${EST_CACERTS_VECTOR}
    Should Contain    ${wrapped.decode('ascii')}    \n
    ${der}=    Decode EST Message Body    ${wrapped}
    Should Not Be Empty    ${der}

# ---------------------------------------------------------------------------
# RFC 7030 Section 4.1 - Distribution of CA certificates (/cacerts)
# ---------------------------------------------------------------------------
CACerts Response Must Parse As A Certs-Only CMS Bundle
    [Documentation]    RFC 7030 Section 4.1.3: a /cacerts response is a base64-encoded certs-only
    ...    CMC Simple PKI Response (a degenerate CMS SignedData with certificates and no
    ...    signerInfos). Parsing the bundled vector must yield the CA certificate.
    [Tags]    est-offline    rfc7030-4.1
    ${body}=    Load EST Test Vector    ${EST_CACERTS_VECTOR}
    ${certs}=    Parse EST CACerts Response    ${body}
    Length Should Be    ${certs}    1
    Should Not Be Empty    ${certs}[0]

# ---------------------------------------------------------------------------
# RFC 7030 Section 4.2 - Client certificate request (/simpleenroll)
# ---------------------------------------------------------------------------
Simple Enroll Request Body Must Be Base64 PKCS#10
    [Documentation]    RFC 7030 Section 4.2.1: the /simpleenroll request body is a single PKCS#10
    ...    structure, base64-encoded. The wrapped body must decode back to the original CSR DER.
    [Tags]    est-offline    rfc7030-4.2
    ${csr_b64}=    Load EST Test Vector    ${EST_CSR_VECTOR}
    ${csr_der}=    Decode EST Message Body    ${csr_b64}
    ${body}=    Build EST Enroll Request Body    ${csr_der}
    ${decoded}=    Decode EST Message Body    ${body}
    Should Be Equal    ${decoded}    ${csr_der}

# ---------------------------------------------------------------------------
# RFC 7030 Section 4.5 - CSR attributes (/csrattrs)
# ---------------------------------------------------------------------------
Empty CSR Attributes Response Means No Required Attributes
    [Documentation]    RFC 7030 Section 4.5.2: an empty body (or HTTP 204) signals that the
    ...    server requires no additional attributes in the certification request.
    [Tags]    est-offline    rfc7030-4.5
    ${oids}=    Parse EST CSR Attributes Response    ${EMPTY}
    Should Be Empty    ${oids}

# ---------------------------------------------------------------------------
# RFC 7030 - Live server interaction (opt-in, needs a server at ${EST_BASE_URL})
# ---------------------------------------------------------------------------
Server Must Return A Certs-Only Bundle For CACerts
    [Documentation]    RFC 7030 Section 4.1: GET /cacerts must return HTTP 200 with an
    ...    application/pkcs7-mime certs-only bundle. Requires a live EST server.
    [Tags]    est-server    rfc7030-4.1
    ${resp}=    Send EST CACerts Request
    Should Be Equal As Integers    ${resp.status_code}    200
    EST Response Must Use Content Type    ${resp}    application/pkcs7-mime
    ${certs}=    Parse EST CACerts Response    ${resp.content}
    Should Not Be Empty    ${certs}

Server Must Issue A Certificate For Simple Enroll
    [Documentation]    RFC 7030 Section 4.2.1/4.2.3: POST /simpleenroll with a PKCS#10 must return
    ...    a certs-only bundle containing the newly issued certificate. Requires a live EST server.
    [Tags]    est-server    rfc7030-4.2
    ${key}    ${csr}=    Generate EST Client CSR    CN=est-simpleenroll.example.com
    ${resp}=    Send EST Enroll Request    ${csr}    simpleenroll
    Should Be Equal As Integers    ${resp.status_code}    200
    EST Response Must Use Content Type    ${resp}    application/pkcs7-mime
    ${certs}=    Parse EST Enroll Response    ${resp.content}
    Length Should Be    ${certs}    1
    ${cert}=    Parse EST Certificate    ${certs}[0]
    Should Not Be Empty    ${cert}

Server Must Issue A Certificate For Simple Reenroll
    [Documentation]    RFC 7030 Section 4.2.2: POST /simplereenroll must also return a certs-only
    ...    bundle with an issued certificate. Requires a live EST server.
    [Tags]    est-server    rfc7030-4.2
    ${key}    ${csr}=    Generate EST Client CSR    CN=est-reenroll.example.com
    ${resp}=    Send EST Enroll Request    ${csr}    simplereenroll
    Should Be Equal As Integers    ${resp.status_code}    200
    ${certs}=    Parse EST Enroll Response    ${resp.content}
    Length Should Be    ${certs}    1

Server Must Answer CSR Attributes Request
    [Documentation]    RFC 7030 Section 4.5: GET /csrattrs must return either HTTP 200 with an
    ...    application/csrattrs body or HTTP 204 when no attributes are required.
    [Tags]    est-server    rfc7030-4.5
    ${resp}=    Send EST CSR Attributes Request
    Should Contain Any    ${{str($resp.status_code)}}    200    204
    IF    ${resp.status_code} == 200
        EST Response Must Use Content Type    ${resp}    application/csrattrs
        ${oids}=    Parse EST CSR Attributes Response    ${resp.content}
        Log    Server advertised CSR attributes: ${oids}
    END

Server Must Generate Key And Issue Certificate For Server Keygen
    [Documentation]    RFC 7030 Section 4.4: POST /serverkeygen must return a multipart/mixed body
    ...    with the server-generated private key and the issued certificate.
    [Tags]    est-server    rfc7030-4.4
    ${key}    ${csr}=    Generate EST Client CSR    CN=est-serverkeygen.example.com
    ${resp}=    Send EST Server Keygen Request    ${csr}
    Should Be Equal As Integers    ${resp.status_code}    200
    EST Response Must Use Content Type    ${resp}    multipart/mixed
    ${ct}=    Get From Dictionary    ${resp.headers}    Content-Type
    ${priv_key}    ${certs}=    Parse EST Server Keygen Response    ${ct}    ${resp.content}
    Should Not Be Empty    ${priv_key}
    Length Should Be    ${certs}    1
