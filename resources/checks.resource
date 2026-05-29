# SPDX-FileCopyrightText: Copyright 2024 Siemens AG   # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
*** Settings ***
Documentation      Concrete Robot Framework implementations of the CMP message validation
...                keywords that previously lived as opaque Python orchestrators in
...                `resources/checkutils.py`. Splitting the orchestration into pure RF makes
...                the test-suite self-documenting: a reader can see which sub-checks each
...                validator performs and can reuse the individual pieces from their own
...                test cases.
...
...                The atomic, low-level Python checks (which still do the heavy ASN.1 and
...                cryptographic inspection) are exposed under `_Atomic ...` names from
...                `checkutils.py` and called by the orchestrators below.

Library             Collections
Library             ../resources/checkutils.py


*** Keywords ***
# =========================================================================
# Header validation cluster
# =========================================================================

Check Is Protection Present
    [Documentation]    Checks whether the `protection` and `protectionAlg` fields of a
    ...                `PKIMessage` are consistently set, per RFC 9480 Section 3.1.
    ...                Returns `True` if both fields are present, `False` if both are
    ...                absent. Fails if exactly one of them is set.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message`: The PKIMessage to inspect.
    ...                - `must_be_protected`: If `${True}`, fails when no protection is
    ...                  present. Defaults to `${False}`.
    ...                - `lwcmp`: If `${True}`, additionally validates that the protection
    ...                  algorithm is one of the lightweight CMP-allowed types (RSA, ECDSA,
    ...                  Ed25519/Ed448, RSASSA-PSS, pbmac1, password-based MAC).
    ...
    ...                Examples:
    ...                ---------
    ...                | ${is_present}=    Check Is Protection Present | ${pki_message} |
    ...                | Check Is Protection Present | ${pki_message} | must_be_protected=${True} |
    [Tags]    header    protection    cmp
    [Arguments]    ${pki_message}    ${must_be_protected}=${False}    ${lwcmp}=${False}
    ${result}=    _Atomic Check Is Protection Present    ${pki_message}
    ...    must_be_protected=${must_be_protected}    lwcmp=${lwcmp}
    RETURN    ${result}

Check Sender CMP Protection
    [Documentation]    Validates the `sender` field of a `PKIMessage` according to
    ...                RFC 9483 Section 3.1.
    ...
    ...                For signature-based protection, the `sender` must match the subject
    ...                DN of the CMP-protection certificate (the first entry of `extraCerts`).
    ...                For MAC-based and KEM-based protection, the `sender` must be a
    ...                `directoryName` containing a commonName.
    ...
    ...                Does NOT check the `senderKID` field — use `Validate senderKID For
    ...                CMP Protection` for that.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message`: The PKIMessage to validate.
    ...                - `must_be_protected`: If `${True}`, fails when no protection is set.
    ...                  Defaults to `${True}`.
    ...                - `allow_failure`: If `${True}`, sender mismatches for MAC- and
    ...                  signature-based protection produce a warning instead of failing.
    ...                  Defaults to `${True}`.
    ...
    ...                Examples:
    ...                ---------
    ...                | Check Sender CMP Protection | ${response} |
    ...                | Check Sender CMP Protection | ${response} | allow_failure=${False} |
    [Tags]    header    protection    sender    cmp
    [Arguments]    ${pki_message}    ${must_be_protected}=${True}    ${allow_failure}=${True}
    _Atomic Check Sender CMP Protection    ${pki_message}
    ...    must_be_protected=${must_be_protected}    allow_failure=${allow_failure}

Validate senderKID For CMP Protection
    [Documentation]    Validates the `senderKID` field of a `PKIMessage` according to
    ...                RFC 9480 Section 3.1.
    ...
    ...                For signature-based protection, `senderKID` must match the
    ...                SubjectKeyIdentifier extension of the CMP-protection certificate.
    ...                For MAC- and KEM-based protection, `senderKID` must equal the
    ...                commonName carried in the `sender` directoryName.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message`: The PKIMessage to validate.
    ...                - `protection_cert`: Optional certificate used for signature
    ...                  protection. Defaults to `${None}`, which uses `extraCerts[0]`.
    ...                - `must_be_protected`: If `${True}`, fails when no protection is set.
    ...                  Defaults to `${False}`.
    ...                - `allow_mac_failure`: If `${True}`, MAC mismatches produce a warning
    ...                  instead of failing. Defaults to `${False}`.
    ...
    ...                Examples:
    ...                ---------
    ...                | Validate senderKID For CMP Protection | ${response} |
    ...                | Validate senderKID For CMP Protection | ${response} | must_be_protected=${True} |
    [Tags]    header    protection    senderkid    cmp
    [Arguments]    ${pki_message}    ${protection_cert}=${None}    ${must_be_protected}=${False}
    ...    ${allow_mac_failure}=${False}
    _Atomic Validate senderKID For CMP Protection    ${pki_message}
    ...    protection_cert=${protection_cert}    must_be_protected=${must_be_protected}
    ...    allow_mac_failure=${allow_mac_failure}

Check implicitConfirm In generalInfo
    [Documentation]    Validates that `implicitConfirm` in the `generalInfo` field of a
    ...                `PKIMessage` is set correctly per RFC 9483 Section 3.1.
    ...
    ...                `implicitConfirm` may only appear in `ip`, `cp`, `kup`, `ir`, `cr`,
    ...                `kur`, and `p10cr` messages. When present, its value MUST be `NULL`.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message`: The PKIMessage to inspect.
    ...
    ...                Examples:
    ...                ---------
    ...                | Check implicitConfirm In generalInfo | ${pki_message} |
    [Tags]    header    generalinfo    cmp
    [Arguments]    ${pki_message}
    _Atomic Check implicitConfirm In generalInfo    ${pki_message}

Check confirmWaitTime In generalInfo
    [Documentation]    Validates that `confirmWaitTime` in the `generalInfo` field of a
    ...                `PKIMessage` is set correctly per RFC 9483 Section 3.1.
    ...
    ...                `confirmWaitTime` MUST NOT be present together with `implicitConfirm`.
    ...                When present, it must be a valid GeneralizedTime.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message`: The PKIMessage to inspect.
    ...
    ...                Examples:
    ...                ---------
    ...                | Check confirmWaitTime In generalInfo | ${pki_message} |
    [Tags]    header    generalinfo    cmp
    [Arguments]    ${pki_message}
    _Atomic Check confirmWaitTime In generalInfo    ${pki_message}

Check certProfile In generalInfo
    [Documentation]    Validates that `certProfile` in the `generalInfo` field of a
    ...                `PKIMessage` is set correctly per RFC 9483 Section 3.1.
    ...
    ...                `certProfile` is optional and may only appear in messages of type
    ...                `ir`, `cr`, `kur`, `p10cr`, and `genm`.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message`: The PKIMessage to inspect.
    ...
    ...                Examples:
    ...                ---------
    ...                | Check certProfile In generalInfo | ${pki_message} |
    [Tags]    header    generalinfo    cmp
    [Arguments]    ${pki_message}
    _Atomic Check certProfile In generalInfo    ${pki_message}

Check generalInfo Field
    [Documentation]    Validates the entire `generalInfo` field of a `PKIMessage` header
    ...                per RFC 9483 Section 3.1 by running each of the three sub-checks
    ...                in sequence. Fails on the first violation.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message`: The PKIMessage to inspect.
    ...
    ...                Examples:
    ...                ---------
    ...                | Check generalInfo Field | ${pki_message} |
    [Tags]    header    generalinfo    cmp    orchestrator
    [Arguments]    ${pki_message}
    Check implicitConfirm In generalInfo    ${pki_message}
    Check confirmWaitTime In generalInfo    ${pki_message}
    Check certProfile In generalInfo    ${pki_message}

Validate transactionID
    [Documentation]    Validates the `transactionID` field of a `PKIMessage` per
    ...                RFC 9483 Section 3.1. The transactionID must be exactly 128 bits
    ...                (16 bytes). If a request is provided, the response transactionID
    ...                must equal the request transactionID.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `response`: The PKIMessage whose `transactionID` is checked.
    ...                - `request`: Optional original request for transactionID matching.
    ...                  Defaults to `${None}`.
    ...
    ...                Examples:
    ...                ---------
    ...                | Validate transactionID | ${response} |
    ...                | Validate transactionID | ${response} | ${request} |
    [Tags]    header    transactionid    cmp
    [Arguments]    ${response}    ${request}=${None}
    _Atomic Validate transactionID    ${response}    request=${request}

Validate Sender And Recipient
    [Documentation]    Validates the sender/recipient and transactionID/nonce correlation
    ...                between a request and its response per RFC 9483 Section 3.1. Runs
    ...                three sub-checks in sequence:
    ...
    ...                1. `Validate transactionID` — IDs of request and response must match.
    ...                2. `Validate Sender And Recipient Nonce` — nonces must correlate.
    ...                3. `recipient` of the response must equal `sender` of the request
    ...                   (when `must_be_eq` is `${True}`, a mismatch fails; otherwise a
    ...                   mismatch only logs a warning).
    ...
    ...                Arguments:
    ...                ---------
    ...                - `response`: The PKIMessage response.
    ...                - `request`: The PKIMessage request that triggered the response.
    ...                - `must_be_eq`: If `${True}`, recipient/sender mismatch fails the
    ...                  check; otherwise it only warns. Defaults to `${False}`.
    ...
    ...                Examples:
    ...                ---------
    ...                | Validate Sender And Recipient | ${response} | ${request} |
    ...                | Validate Sender And Recipient | ${response} | ${request} | must_be_eq=${True} |
    [Tags]    header    sender    recipient    cmp    orchestrator
    [Arguments]    ${response}    ${request}    ${must_be_eq}=${False}
    _Atomic Validate Sender And Recipient    ${response}    ${request}    must_be_eq=${must_be_eq}

Validate PKIMessage Header
    [Documentation]    Validates a `PKIMessage` header for conformance with RFC 9483
    ...                Section 3.1. Runs each sub-check in sequence; fails on the first
    ...                violation. The sequence is:
    ...
    ...                1. `pvno` must be 2 or 3.
    ...                2. `Check Is Protection Present` — protection consistency.
    ...                3. `Check Sender CMP Protection` — sender field correctness.
    ...                4. `Validate senderKID For CMP Protection` — senderKID correctness.
    ...                5. `Check generalInfo Field` — implicitConfirm/confirmWaitTime/certProfile.
    ...                6. `messageTime` — must be present when `confirmWaitTime` is set,
    ...                    and within the allowed interval relative to request time.
    ...                7. `Validate Sender And Recipient` — only if a request is supplied.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `response`: The PKIMessage response to validate.
    ...                - `request`: Optional original request used for transactionID,
    ...                  sender, and timestamp correlation. Defaults to `${None}`.
    ...                - `protection`: Whether protection must be present on the response.
    ...                  Defaults to `${True}`.
    ...                - `time_interval`: Maximum allowed seconds between request and
    ...                  response `messageTime`. Set to `${None}` to disable. Defaults
    ...                  to `200`.
    ...                - `allow_failure_sender`: If `${True}`, sender / senderKID mismatches
    ...                  for MAC-based protection produce warnings instead of failing.
    ...                  Defaults to `${True}`.
    ...
    ...                Examples:
    ...                ---------
    ...                | Validate PKIMessage Header | ${response} | ${request} |
    ...                | Validate PKIMessage Header | ${response} | ${request} | time_interval=95000 |
    ...                | Validate PKIMessage Header | ${response} | protection=${False} |
    [Tags]    header    cmp    orchestrator
    [Arguments]    ${response}    ${request}=${None}    ${protection}=${True}
    ...    ${time_interval}=200    ${allow_failure_sender}=${True}
    ${pvno}=    Evaluate    int($response["header"]["pvno"])
    IF    ${pvno} not in [2, 3]
        Fail    Header version is ${pvno}, expected 2 or 3
    END
    Check Is Protection Present    ${response}    must_be_protected=${protection}
    Check Sender CMP Protection    ${response}
    ...    must_be_protected=${protection}    allow_failure=${allow_failure_sender}
    Validate senderKID For CMP Protection    ${response}
    ...    must_be_protected=${protection}    allow_mac_failure=${allow_failure_sender}
    Check generalInfo Field    ${response}
    Check messageTime Field    ${response}    request=${request}    time_interval=${time_interval}
    IF    $request is not None
        Validate Sender And Recipient    ${response}    ${request}    must_be_eq=${False}
    END

Check messageTime Field
    [Documentation]    Validates the `messageTime` field of a `PKIMessage` per RFC 9483
    ...                Section 3.1. Specifically:
    ...
    ...                - When the message carries a `confirmWaitTime` in `generalInfo`,
    ...                  the `messageTime` field MUST be present.
    ...                - When `time_interval` is given, the message time must lie within
    ...                  that many seconds of either the supplied request time or
    ...                  (when no request is given) the current UTC time. A negative
    ...                  difference (response in the future) fails.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message`: The PKIMessage to inspect.
    ...                - `request`: Optional originating request whose `messageTime` is
    ...                  used as the reference point. Defaults to `${None}`.
    ...                - `time_interval`: Allowed time difference in seconds. Set to
    ...                  `${None}` to disable the bound check. Defaults to `${None}`.
    ...
    ...                Examples:
    ...                ---------
    ...                | Check messageTime Field | ${response} |
    ...                | Check messageTime Field | ${response} | request=${request} | time_interval=200 |
    [Tags]    header    messagetime    cmp
    [Arguments]    ${pki_message}    ${request}=${None}    ${time_interval}=${None}
    ${request_time}=    Set Variable    ${None}
    IF    $request is not None and $request["header"]["messageTime"].isValue
        ${request_time}=    Evaluate    $request["header"]["messageTime"].asDateTime
    END
    ${interval}=    Set Variable    ${time_interval}
    IF    $interval is not None
        ${interval}=    Convert To Integer    ${interval}
    END
    _Atomic Check messageTime Field    ${pki_message}
    ...    allowed_interval=${interval}    request_time=${request_time}
