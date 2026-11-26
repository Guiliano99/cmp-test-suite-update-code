---
name: prepare-asn1-structure-unit-tests
description: "Add or update Python unit tests for functions that build or parse pyasn1 ASN.1 structures, such as prepare_* builders. The tests need a DER encode and decode round trip, positive field assertions and negative-path checks, and a reading by another implementation where the repository asks for it. Use when testing ASN.1 structure builders in the cmp-test-suite. Do not use for generic unittest style tasks that have no DER round trip."
metadata:
  internal: true
---

# Prepare ASN.1 Structure Unit Tests

Use this skill when writing tests for functions that build or parse ASN.1 structures.

## Start here

Read the profile of your repository first. It names the builders, the test folders, the calls a test uses to encode
and decode, the commands, and what else has to read the structure.

- `profiles/cmp-test-suite.md` for the cmp-test-suite.

Skills that help, if they are installed next to this one: `python-unit-test-given-when-then` for the
GIVEN/WHEN/THEN style of a test, `write-unit-tests` for where a test of one new function goes, and `auditing-pyasn1`
for the pyasn1 rules of the code under test.

## Quick workflow

1. Select the test folder and a neighboring test file (profile).
2. Draft the scenarios with [FORMS.md](FORMS.md).
3. Add at least one DER round-trip test per target (rule below).
4. Add positive field assertions for the required components.
5. Add one negative-path test for invalid input or missing required values.
6. Run the checker and the tests (commands in the profile).

## Round-trip rule

In each test file for builders, at least one test function:

1. creates a structure with the builder;
2. encodes it: `encoder.encode(...)`, `encode_to_der(...)`;
3. decodes it with its spec, and shows that no bytes remain: `decoder.decode(data, asn1Spec=<Type>())` and
   `rest == b""`, or `decode_der(data, <Type>())`, which refuses bytes after the structure and BER that is not DER;
4. asserts the fields it decoded.

A round trip proves only that encoder and decoder agree. The profile says what else has to read what the builder
makes, and what the builder has to read.

## The checker

```bash
.venv/bin/python .agents/skills/prepare-asn1-structure-unit-tests/scripts/check_prepare_asn1_roundtrip.py <path>... [--pattern GLOB]
```

- It checks the files below the paths whose name matches `--pattern` (default `test_prepare_*.py`).
- A file passes if one of its test functions has an encode call, a decode call with a spec, and either an assertion
  that `rest` is empty or a call of `decode_der`. The calls it knows: `encoder.encode`, `encode_to_der`,
  `try_encode_pyasn1`, `decoder.decode`, `try_decode_pyasn1`, `decode_der`.
- Exit codes: 0 no violation, 1 a violation, 2 no file matched the pattern (the message is on stderr).
- It looks inside the test functions only. A round trip in a helper function of the file is not seen.
- It shows that a round trip exists, not that it is the right one.

## Validation loop

1. Run the checker on the changed test files.
2. Run the changed tests, then the whole suite of the repository (profile).
3. Fix failures and run again.

## Files in this skill

- `SKILL.md` - workflow and rules.
- `FORMS.md` - draft form and test templates.
- `profiles/` - what is specific to a repository.
- `scripts/check_prepare_asn1_roundtrip.py` - the checker.

## Completion checklist

- [ ] The builder and the test file or folder were found.
- [ ] A DER round-trip test covers the structure, and the checker passes on the file.
- [ ] The tests read the structure with the other implementation that the profile names.
- [ ] Positive field assertions and a negative-path test are there.
- [ ] The changed tests and the whole suite were run, or the report says they are pending.
