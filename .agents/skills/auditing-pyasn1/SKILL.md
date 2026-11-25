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
4. Go through the pattern checklist for every changed line that touches an ASN.1
   object.
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

### 2. Variables: `is None`. Fields: `isValue`. Never truthiness
Never test an ASN.1 object with `if value:` or `if not value:`. A valid object can
count as false, and an unset one counts as false or raises `PyAsn1Error`, depending
on its type. `is None` asks whether
you hold an object at all. `isValue` asks whether that object carries a value.

Use:
```python
# a variable or argument that may be None or hold an ASN.1 object
if extensions is None:
    extensions = rfc5280.Extensions()

# a field of a structure
if structure["field"].isValue:      # present, possibly empty
    ...
if not structure["field"].isValue:  # absent
    ...
```

Do not use:
```python
if not extensions:              # replaces an empty object that the caller passed
    extensions = rfc5280.Extensions()
if structure["field"] is None:  # never true: an absent field is a schema object
    ...
if structure["field"]:          # false for a present but empty field, may raise
    ...
```

These values count as false but are valid: `Integer(0)`, `Boolean(False)`,
`OctetString(b"")`, `BitString("")`, `Null("")` and an empty SEQUENCE OF.

Exceptions for fields:
- A SEQUENCE whose fields are all optional (for example `validity` in
  `CertTemplate`) has `isValue == True` even when it is absent. Check its fields:
  `any(value[name].isValue for name in value)`.
- A DEFAULT field (for example `cA` in `BasicConstraints`) always has
  `isValue == True`. Compare its value instead.

### 3. BitString handling
Use the method appropriate to the pyasn1 object:
- `.asOctets()` for extracting bytes from a BitString/OctetString.
- Not for named bits such as keyUsage: `BitString("101").asOctets()` is `05`, but the
  DER content is `a0`. Use `asn1utils.is_bit_set` or
  `asn1utils.get_set_bitstring_names`.

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

## Pattern checklist

| Use | Instead of | Reason |
|---|---|---|
| `if obj is None:` for a variable or argument | `if not obj:` | an empty or zero object counts as false |
| `obj["field"].isValue` | `obj["field"] is None`, `if obj["field"]:` | an absent field is a schema object |
| `isValue` before `getName()` or `getComponent()` of a CHOICE | reading it directly | an unset CHOICE raises `Component not chosen` |
| `bool(bc["cA"])` for a DEFAULT field | `bc["cA"].isValue` | a DEFAULT field always has a value |
| `obj["field"]`, `obj["field"] = value` | `getComponentByName`, `setComponentByName` | same object, easier to read; keep the method if you need its extra arguments |
| `.asOctets()` or `get_asn1_value_as_bytes` | `str()`, `prettyPrint()` | only these return the bytes |
| `is_bit_set`, `get_set_bitstring_names` for named bits | `.asOctets()` | the bytes differ from the DER content; `is_bit_set` checks for exactly these bits unless `exclusive=False` |
| `asn1utils` accessors | new path logic | one tested access layer |
| `try_decode_pyasn1`, then reject a non-empty `rest` | ignoring `rest` | the decoder accepts trailing bytes |
| types and OIDs from `pyasn1-alt-modules` | local classes, literal OIDs | one definition |
| `datetime` without microseconds | `datetime.now()` directly | RFC 5280 Section 4.1.2.5.2 forbids fractional seconds |
| DER encode and decode in the unit test | comparing the object only | wrong tags show up only in DER |

## Files in this skill

- `SKILL.md` - Audit guidance and rules.
- `agents/openai.yaml` - Discovery metadata.
- `.tags` - Index tags.

## Completion checklist

- [ ] GeneralizedTime inputs do not retain milliseconds.
- [ ] The pattern checklist was applied to every changed line.
- [ ] Variables and arguments use `is None`, fields use `isValue`, nothing uses truthiness.
- [ ] BitString/OctetString values use `.asOctets()` or asn1utils accessors.
- [ ] New code uses `asn1utils.py` accessors where applicable.
- [ ] DER encoding and decoding is covered for prepared values.
- [ ] All combinations are covered by unit tests.
- [ ] Tagging is verified.
- [ ] pyasn1-alt-modules is used where possible.
- [ ] Prepare helpers have meaningful tests.
- [ ] Relevant unit tests pass.
