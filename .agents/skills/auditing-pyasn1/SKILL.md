---
name: auditing-pyasn1
description: >-
  Audit and update pyasn1/OpenSSL preparation code in the cmp-test-suite
  codebase. Use when reviewing prepare_* helpers, BitString and
  OctetString handling, GeneralizedTime values, None checks, or when new code
  accesses pyasn1 values and Python types.
---

# Auditing pyasn1 Code

Use this skill when reviewing or modifying code that constructs, reads, or
compares pyasn1 objects.

## Quick workflow

1. Locate the prepare helper and all callers before changing behavior.
2. Prefer reuse of existing helpers in `prepareutils.py`, `asn1utils.py`,
   and `asn1obj.py`.
3. Verify datetime preparation strips microseconds/seconds appropriately.
4. Check optional pyasn1 fields with `isValue`, not truthiness or `is None`.
5. Use accessors from `resources/asn1utils.py` for value and Python-type
   extraction.
6. Run unit tests and, where possible, DER round-trip checks.

## Mandatory rules

### 1. GeneralizedTime must not carry microseconds
Preparation helpers must strip milliseconds before converting. In
`prepare_generalized_time`, `_prepare_date_time_object` uses
`datetime.replace(microsecond=0)`. Keep this behavior when refactoring or
adding new generalized-time helpers.

Do:
- ensure aware or naive datetime values are normalized correctly
- preserve the UTC conversion behavior

Do not:
- pass `datetime.now()` directly without stripping microseconds
- accidentally use a float timestamp carrying sub-second precision

### 2. Check optional pyasn1 fields with `isValue`
Reading an absent optional field does not return `None`. pyasn1 returns a schema
object without a value, so `is None` is never true for it. Truthiness is wrong
too: `if value:` raises `PyAsn1Error` for most absent types, and it is false for a
field that is present but empty.

Use:
```python
if structure["field"].isValue:      # present, possibly empty
    ...
if not structure["field"].isValue:  # absent
    ...
```

Do not use:
```python
if structure["field"] is None:
    ...
if structure["field"]:
    ...
```

Exceptions:
- A SEQUENCE whose fields are all optional (for example `validity` in
  `CertTemplate`) has `isValue == True` even when it is absent. Check its fields:
  `any(value[name].isValue for name in value)`.
- A DEFAULT field (for example `cA` in `BasicConstraints`) always has
  `isValue == True`. Compare its value instead.
- `is None` is correct for Python values that can be `None`, such as optional
  function arguments and the results of helper functions.

This applies to optional pyasn1 fields, certificate extensions, OCTET STRINGs,
and BitStrings.

### 3. BitString handling
Use the method appropriate to the pyasn1 object:
- `.asOctets()` for extracting bytes from a BitString/OctetString.

Preferred in new code logic:
- `asn1utils.get_asn1_value_as_bytes(...)` for repository-supported access to
  BitString and OctetString values.

### 4. OctetString handling
When assigning or comparing OctetString content, prefer:
- direct pyasn1 assignment when creating structures
- `get_asn1_value_as_bytes()` when reading values in Python
- explicit bytes helpers rather than ad-hoc `.prettyPrint()` conversions

### 5. asn1utils.py is the access layer
For new code logic, use `resources/asn1utils.py` helpers where possible:
- `get_asn1_value`
- `get_asn1_value_as_string`
- `get_asn1_value_as_number`
- `get_asn1_value_as_bytes`
- `get_asn1_value_as_datetime`

Use these helpers for reading values and corresponding Python types from
BitStrings and OctetStrings instead of introducing custom path logic.

### 6. Unit-test and DER requirements
When adding or changing prepare helpers:

- test positive and negative paths
- test malformed input rejection
- test DER encoding and DER decoding of the prepared value
- test all relevant shape and input combinations
- test canonical tagging and tag context correctness
- test milliseconds are removed for GeneralizedTime
- test absent and present-but-empty fields, and `None` arguments, explicitly

New code must not only call a helper successfully. It must also prove that the
resulting value round-trips through DER encoding and decoding, and that the
correct ASN.1 tagging is used for every supported combination.

### 7. pyasn1-alt-modules must be preferred for reusable structures
When a referenced RFC type is already available through `pyasn1-alt-modules`,
use it instead of redefining the same structure in local code.

- import reusable RFC types from `pyasn1-alt-modules` whenever possible
- only define a local structure when no suitable alt-modules type exists
- document the RFC source of imported types
- keep local type definitions minimal and reuse the imported substructures


## Files in this skill

- `SKILL.md` - Audit guidance and rules.
- `agents/openai.yaml` - Discovery metadata.
- `.tags` - Index tags.

## Completion checklist

- [ ] GeneralizedTime inputs do not retain milliseconds.
- [ ] Optional pyasn1 fields use `isValue`; `is None` is only used for Python values.
- [ ] BitString/OctetString values use `.asOctets()` or asn1utils accessors.
- [ ] New code uses `asn1utils.py` accessors where applicable.
- [ ] DER encoding and decoding is covered for prepared values.
- [ ] All combinations are covered by unit tests.
- [ ] Tagging is verified.
- [ ] pyasn1-alt-modules is used where possible.
- [ ] Prepare helpers have meaningful tests.
- [ ] Relevant unit tests pass.
