# SPDX-FileCopyrightText: Copyright 2024 Siemens AG   # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
*** Settings ***
Documentation       High-level CMP validation keywords, written in plain Robot Framework so that
...                 RFC and PKI experts can read, understand, and reuse them without reading any
...                 Python. Each keyword below is an *orchestrator*: it spells out, step by step,
...                 the checks that a section of the RFC requires, by calling the smaller checks
...                 that already exist in `checkutils.py`.
...
...                 The intent is a small, self-documenting surface: a test author normally only
...                 needs the orchestrators here (for example `Validate PKIMessage Header`), and
...                 can read this file to see exactly which sub-checks each one performs.

Library             ../resources/checkutils.py
Library             ../resources/asn1utils.py


*** Keywords ***
Validate PKIMessage Header
    [Documentation]    Validate a `PKIMessage` header for conformance with RFC 9483 Section 3.1.
    ...
    ...                This keyword performs, in order, every header check the RFC requires and
    ...                fails on the first violation. Read the steps below to see what "a valid
    ...                header" means; call the individual steps directly if you only need one.
    ...
    ...                Steps:
    ...                1. The protocol version (`pvno`) must be 2 or 3.
    ...                2. Protection (`protection` + `protectionAlg`) must be consistently set.
    ...                3. The `sender` field must match the protection (certificate subject for
    ...                   signature protection, commonName for MAC/KEM protection).
    ...                4. The `senderKID` must match the protection certificate / commonName.
    ...                5. The `generalInfo` field (implicitConfirm / confirmWaitTime / certProfile)
    ...                   must be set as allowed for the message type.
    ...                6. The `messageTime` must be present when required and within the allowed
    ...                   time window relative to the request.
    ...                7. When a request is supplied, the `transactionID`, nonces, and the
    ...                   sender/recipient correlation between request and response must match.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `response`: The `PKIMessage` whose header is validated.
    ...                - `request`: The original request `PKIMessage`, used to correlate
    ...                  transactionID, nonces, sender/recipient, and messageTime. Defaults to
    ...                  `${None}` (response-only validation).
    ...                - `protection`: Whether the response must be protected. Defaults to `${True}`.
    ...                - `time_interval`: Maximum allowed seconds between the request and response
    ...                  `messageTime`. Set to `${None}` to skip the time-window check. Defaults
    ...                  to `200`.
    ...                - `allow_failure_sender`: If `${True}`, `sender` / `senderKID` mismatches for
    ...                  MAC-based protection produce a warning instead of failing. Defaults to
    ...                  `${True}`.
    ...
    ...                Examples:
    ...                ---------
    ...                | Validate PKIMessage Header | ${response} | ${request} |
    ...                | Validate PKIMessage Header | ${response} | ${request} | time_interval=95000 |
    ...                | Validate PKIMessage Header | ${response} | protection=${False} |
    [Tags]    header    cmp    rfc9483
    [Arguments]    ${response}    ${request}=${None}    ${protection}=${True}
    ...    ${time_interval}=200    ${allow_failure_sender}=${True}
    ${pvno}=    Get Asn1 Value As Number    ${response}    header.pvno
    IF    ${pvno} not in [2, 3]
        Fail    PKIMessage header version is ${pvno}, expected 2 or 3 (RFC 9483 Section 3.1).
    END
    Check Is Protection Present    ${response}    must_be_protected=${protection}
    Check Sender CMP Protection    ${response}
    ...    must_be_protected=${protection}    allow_failure=${allow_failure_sender}
    Validate senderKID For CMP Protection    ${response}
    ...    must_be_protected=${protection}    allow_mac_failure=${allow_failure_sender}
    Check generalInfo Field    ${response}
    Check messageTime Field    ${response}    allowed_interval=${time_interval}    request=${request}
    IF    $request is not None
        Validate Sender And Recipient    ${response}    ${request}
    END
