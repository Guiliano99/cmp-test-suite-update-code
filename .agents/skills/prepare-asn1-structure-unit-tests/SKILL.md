---
name: prepare-asn1-structure-unit-tests
description: "Add or update Python unit tests for prepare_* pyasn1 builders, requiring DER encode/decode round-trip assertions plus behavior and negative-path checks. Use when testing ASN.1 structure builder functions in this CMP repository. Do not use for generic unittest style-only tasks that lack prepare_* DER round-trip requirements."
metadata:
  internal: true
---

# Prepare ASN.1 Structure Unit Tests

Use this skill when writing tests for `prepare_*` functions that build ASN.1
objects.

## Boundary and handoff

- Use this skill only for `prepare_*` pyasn1 builder tests with DER round-trip requirements.
- Use [python-unit-test-given-when-then](../../python-skills/python-unit-test-given-when-then/SKILL.md) for generic GWT style enforcement in non-ASN.1 tests.
- Use [write-unit-tests](../../python-skills/write-unit-tests/SKILL.md) for new single-function test file placement when DER round-trip is not required.

## Quick workflow

1. Select the owning `unit_tests/tests_*` suite near the target `prepare_*` function.
2. Draft scenarios with [FORMS.md](FORMS.md).
3. Add at least one DER round-trip test per `prepare_*` target:
   - `encoder.encode(structure)`
   - `decoder.decode(..., asn1Spec=<ExpectedType>())`
   - assert `rest == b""`
4. Add positive field assertions for required components.
5. Add one negative-path test for invalid input or missing required values.
6. Run commands from [reference.md](reference.md), including the checker script.

## Files in this skill

- Workflow: `SKILL.md`
- Draft form and checklist: `FORMS.md`
- Copy/adapt examples: `examples.md`
- Validation commands: `reference.md`
- Round-trip presence checker: `scripts/check_prepare_asn1_roundtrip.py`
- Checker unit tests: `unit_tests/test_check_prepare_asn1_roundtrip.py`

## Required round-trip rule

For each new `test_prepare_*.py` file, include at least one test case that:

1. Creates a structure via `prepare_*`.
2. Encodes it with `encoder.encode(...)`.
3. Decodes it with `decoder.decode(..., asn1Spec=<expected>)`.
4. Asserts `rest == b""`.

## Validation loop

1. Run the round-trip checker on changed test files.
2. Run focused `unittest` discovery for the changed suite.
3. Fix failures and rerun until green.
4. Run broader `unit_tests` discovery before finishing.

## Implementation checklist

1. Pick target suite and neighboring test file.
2. Add or update `test_prepare_*.py`.
3. Add GIVEN/WHEN/THEN docstrings for new test methods.
4. Add required DER encode/decode round-trip test.
5. Add positive field assertions.
6. Add negative-path test.
7. Run round-trip checker script.
8. Run focused `unittest`.
9. Run broader `unit_tests` discovery.
10. Report coverage added.

## Completion checklist

- [ ] The target `prepare_*` builder and owning test suite were identified correctly.
- [ ] DER round-trip coverage was added for the changed structure.
- [ ] Positive field assertions and negative-path tests were included.
- [ ] GIVEN/WHEN/THEN docstrings were used for new test methods.
- [ ] Focused and broader validation commands were run or explicitly reported as pending.

