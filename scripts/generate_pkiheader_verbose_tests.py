# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""Generate test cases for CMP PKIHeader validation."""

import copy
from typing import List

from scripts.gen_test_case_utils import TestCase, get_body_name_tags

LATEST_CMP_VERSION = 3

ALL_BODY_NAMES = [
    "ir",
    "p10cr",
    "cr",
    "kur",
    "genm",
    "ccr",
    "rr",
    "added-protection",
    "added-protection-inner-ir",
    "added-protection-inner-cr",
    "added-protection-inner-kur",
    "added-protection-inner-p10cr",
    "added-protection-inner-ccr",
    "batch",
    "batch_inner_ir",
    "batch_inner_cr",
    "batch_inner_kur",
    "batch_inner_p10cr",
    "batch_inner_ccr",
]
MAC_BODY_NAMES = [
    "ir",
    "p10cr",
    "cr",
    "genm",
    "added-protection-inner-ir",
    "added-protection-inner-cr",
    "added-protection-inner-p10cr",
    "batch_inner_ir",
    "batch_inner_cr",
    "batch_inner_p10cr",
]

PVNO_VERSIONS_TO_CHECK = [2, 3]


def _check_version_support(version: int, allowed_versions: List[int]) -> bool:
    """Check if a version is supported based on the configuration."""
    return version in allowed_versions

def _generate_unsupported_version_test_cases() -> List[TestCase]:
    """Generate test cases for unsupported version 1 validation."""
    test_cases = []
    for version in [1]:
        for body_name in ALL_BODY_NAMES:
            tags = get_body_name_tags(body_name)
            test_case = TestCase(
                name=f"CA MUST Reject {body_name.upper()} With PVNO Set To {version}",
                args=[[body_name, str(version), "unsupportedVersion"]],
                description=f"We send a {body_name.upper()} Request with the version set to 1 and expect the CA to reject the Request."
                            f"A PKIMessage **MUST** have the `version` field set to 2 or 3.\nRef: RFC 9483, Section 3.1.",
                tags=["negative", "pvno", f"pvno={version}", "lwcmp"] + tags,
                functions=["Build With Bad Version"],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_supported_version_test_cases() -> List[TestCase]:
    """Generate test cases for supported version 1-3 validation."""
    test_cases = []
    for version in PVNO_VERSIONS_TO_CHECK:
        if _check_version_support(version, PVNO_VERSIONS_TO_CHECK):
            for body_name in ALL_BODY_NAMES:

                if body_name == "added-protection":
                    # Irrelevant for added-protection, as the version is determined by the inner message.
                    continue

                tags = get_body_name_tags(body_name)
                test_case = TestCase(
                    name=f"CA MUST Accept {body_name.upper()} With PVNO Set To {version}",
                    args=[[body_name, str(version)]],
                    description="A PKIMessage **MUST** have the `version` field set to 2 or 3.\nRef: RFC 9483, Section 3.1.",
                    tags=["positive", "pvno", f"pvno={version}", "lwcmp"] + tags,
                    functions=["Build With Good Version"],
                )
                test_cases.append(test_case)
    return test_cases


def _generate_bad_pvno_test_cases() -> List[TestCase]:
    """Generate test cases for bad version validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A PKIMessage **MUST** have the `version` field set to 2 or 3.\nRef: RFC 9483, Section 3.1."
    for case, func, arg, failinfo in [
        (
            "CA MUST Reject {} With PVNO Set To -1",
            "Build With Bad Version",
            "-1",
            "unsupportedVersion",
        ),
        (
            "CA MUST Reject {} With PVNO Set To 0",
            "Build With Bad Version",
            "0",
            "unsupportedVersion",
        ),
        (
            "CA MUST Reject {} With PVNO Set To Not Defined Value",
            "Build With Bad Version",
            str(LATEST_CMP_VERSION + 1),
            "unsupportedVersion",
        ),
        (
            "CA MUST Reject {} With PVNO Set To Too Large Int",
            "Build With Bad Version",
            str(2**64),
            "badDataFormat",
        ),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name, arg, failinfo]],
                description=description,
                tags=["negative", "pvno"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_sender_nonce_test_cases() -> List[TestCase]:
    """Generate test cases for sender nonce validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1."
    for case, func in [
        (
            "CA MUST Reject {} Without SenderNonce",
            "Build Without senderNonce",
        ),
        ("CA MUST Reject {} With Too Short SenderNonce", "Build With Too Short senderNonce"),
        ("CA MUST Reject {} With Too Long SenderNonce", "Build With Too Long senderNonce"),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "senderNonce"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_recip_nonce_test_cases() -> List[TestCase]:
    """Generate test cases for recipient nonce validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A PKIMessage **MUST** not have a `recipNonce` set. Ref: RFC 9483, Section 3.1."
    for case, func in [
        (
            "CA MUST Reject {} With RecipNonce",
            "Build With recipNonce",
        ),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)
            if body_name == "batch":
                # This requires the CA to verify that this is an initial batch message.
                tags += ["strict", "robot:skip-on-failure"]

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "recipNonce"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_transaction_id_test_cases() -> List[TestCase]:
    """Generate test cases for transaction ID validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.\nRef: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} Without TransactionID",
            "Build Without transactionID",
        ),
        ("CA MUST Reject {} With Too Short TransactionID", "Build With Too Short transactionID"),
        ("CA MUST Reject {} With Too Long TransactionID", "Build With Too Long transactionID"),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "transactionID"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_message_time_test_cases() -> List[TestCase]:
    """Generate test cases for message time validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.\nRef: RFC 9483, Section 3.1."
    for case, func in [
        (
            "CA MUST Reject {} Without MessageTime",
            "Build Without messageTime",
        ),
        ("CA MUST Reject {} With MessageTime In Future", "Build With MessageTime In Future"),
        ("CA MUST Reject {} With MessageTime In Past", "Build With MessageTime In Past"),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "messageTime"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_mac_in_konsistent_test_cases() -> List[TestCase]:
    """Generate test cases for inconsistent MAC message validation."""
    body_names = MAC_BODY_NAMES
    test_cases = []
    description = (
        "A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.\n"
        "Ref: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} With MAC Algorithm without Protection",
            "Build With MAC Alg Without Protection",
        ),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "inconsistent", "protection", "mac"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_in_konsistent_test_cases() -> List[TestCase]:
    """Generate test cases for inconsistent message validation."""
    body_names = copy.copy(ALL_BODY_NAMES)
    test_cases = []
    description = (
        "A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.\n"
        "Ref: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} With Protection without Algorithm",
            "Build With Protection Without Alg",
        ),
        ("CA MUST Reject {} With Sig Algorithm without Protection", "Build With Sig Alg Without Protection"),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            tag = ["protection", "sig"] if "Sig" in func else ["protection"]

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "inconsistent"] + tag + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_sig_protected_test_cases() -> List[TestCase]:
    """Generate test cases for signature protected validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A PKIMessage **MUST** contain the complete cert chain and be valid protected.\nRef: RFC 9483, Section 3.1."
    )
    for case, func, add_tags in [
        ("CA MUST Reject {} With Invalid Sig Protection", "Build With Bad Sig Protection", []),
        (
            "CA MUST Reject {} Without extraCerts",
            "Build Without extraCerts",
            ["extraCerts"],
        ),
        ("CA MUST Reject {} Without Cert Chain", "Build Without Cert Chain", ["extraCerts"]),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "sig", "protection"] + tags + add_tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_neg_validate_header_test_cases() -> List[TestCase]:
    """Generate test cases for validating the CMP PKIHeader."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A PKIMessage **MUST** have a valid `PKIHeader`.\nRef: RFC 9483, Section 3.1."
    for case, func in [
        (
            "CA MUST Return For NEG {} A Valid PKIHeader",
            "Build Message For Negative Header Validation",
        ),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "PKIHeader"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_pos_validate_header_test_cases() -> List[TestCase]:
    """Generate test cases for validating the CMP PKIHeader."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = "A PKIMessage **MUST** have a valid `PKIHeader`.\nRef: RFC 9483, Section 3.1."
    for case, func in [
        (
            "CA MUST Return For POS {} A Valid PKIHeader",
            "Build Message For Positive Header Validation",
        ),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["positive", "PKIHeader"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_sig_sender_kid_test_cases() -> List[TestCase]:
    """Generate test cases for signature sender and senderKID validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A signature protected PKIMessage **MUST** have the senderKID set "
        "the SKI of the protection cert, if present."
        "\nRef: RFC 9483, Section 3.1."
    )
    for case, func in [
        ("CA MUST Reject {} With Invalid SKI SenderKID", "Build With Bad Sig SenderKID"),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "sig", "senderKID"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_sig_sender_test_cases() -> List[TestCase]:
    """Generate test cases for signature sender validation."""
    body_names = ALL_BODY_NAMES
    test_cases = []
    description = (
        "A signature protected PKIMessage **MUST** have the"
        " `sender` field set to the `subject`.\nRef: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} With Invalid Sig Sender",
            "Build With Bad Sig Sender",
        ),
        ("CA MUST Reject {} With Issuer As Sender", "Build With Bad Issuer As Sender"),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "sig", "sender"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_mac_sender_test_cases() -> List[TestCase]:
    """Generate test cases for MAC sender validation."""
    body_names = MAC_BODY_NAMES
    test_cases = []
    description = (
        "A MAC protected PKIMessage **MUST** have the `sender` "
        "field set to the `directoryName` choice.\nRef: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} With Invalid MAC Sender",
            "Build With Bad MAC Sender Choice",
        ),
        ("CA MUST Reject {} Which is Invalid Protected", "Build Bad MAC Protected Message"),
        ("CA MUST Reject {} With Bad MAC SenderKID", "Build With Bad MAC SenderKID"),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)

            tag = "sender" if "SenderKID" not in func else "senderKID"

            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "mac", tag] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def _generate_mac_wrong_integrity_test_cases() -> List[TestCase]:
    """Generate test cases for MAC sender validation."""
    body_names = [
        "added-protection",
        "batch",
        "batch_inner_ccr",
        "batch_inner_kur",
        "added-protection-inner-kur",
        "added-protection-inner-ccr",
        "ccr",
        "kur",
        "rr",
    ]

    test_cases = []
    description = (
        "A MAC protected PKIMessage is not allowed for a `rr` "
        "or `kur`,`ccr` and `nested` messages.\nRef: RFC 9483, Section 3.1."
    )
    for case, func in [
        (
            "CA MUST Reject {} Which Is MAC Protected",
            "Build Not Allowed MAC-Protected Message",
        ),
    ]:
        for body_name in body_names:
            tags = get_body_name_tags(body_name)
            test_case = TestCase(
                name=case.format(body_name.upper()),
                args=[[body_name]],
                description=description,
                tags=["negative", "mac"] + tags,
                functions=[func],
            )
            test_cases.append(test_case)
    return test_cases


def generate_test_case() -> List[str]:
    """Generate all test cases for the CMP `PKIHeader` validation."""
    out = _generate_bad_pvno_test_cases()
    out += _generate_unsupported_version_test_cases()
    out += _generate_supported_version_test_cases()
    out += _generate_sender_nonce_test_cases()
    out += _generate_recip_nonce_test_cases()
    out += _generate_transaction_id_test_cases()
    out += _generate_message_time_test_cases()
    out += _generate_sig_protected_test_cases()
    out += _generate_in_konsistent_test_cases()
    out += _generate_mac_in_konsistent_test_cases()
    out += _generate_sig_sender_test_cases()
    out += _generate_sig_sender_kid_test_cases()
    out += _generate_mac_sender_test_cases()
    out += _generate_mac_wrong_integrity_test_cases()
    out += _generate_neg_validate_header_test_cases()
    out += _generate_pos_validate_header_test_cases()
    return [case.create_test_case() for case in out]


if __name__ == "__main__":
    # Generate test cases and write them to a file
    test_cases = generate_test_case()
    _length = len(test_cases)
    with open("./pki_header_verbose_tests.txt", "w") as f:
        for i, test_case in enumerate(test_cases, 1):
            if i != _length:
                f.write(test_case + "\n")
            else:
                f.write(test_case)
    print(f"Generated {_length} test cases for CMP PKIHeader validation.")