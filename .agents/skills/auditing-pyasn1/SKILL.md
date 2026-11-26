---
name: auditing-pyasn1
description: >-
  Audit code that builds, reads, copies or compares pyasn1 objects: prepare_*
  builders, truth tests on ASN.1 objects, clone(), copy and deepcopy, BIT STRING
  and OCTET STRING values, named bits, GeneralizedTime values, bytes after a
  decode. Use when a change touches pyasn1 or pyasn1-alt-modules objects, in any
  repository that has a profile in profiles/.
---

# Auditing pyasn1 Code

Use this skill when reviewing or changing code that builds, reads, copies or compares pyasn1 objects.

## Start here

1. Read the profile of your repository. It names the helpers, the tests and the checks of that repository.
   - `profiles/cmp-test-suite.md` for the cmp-test-suite.
   - No profile: use the rules below, and find out what the decode and encode helpers of the repository do.
2. Every pyasn1 behaviour stated below is a claim of `scripts/check_pyasn1_facts.py`. The text cites it as [n],
   the number of the claim. Run it from the repository root:

   ```bash
   .venv/bin/python .agents/skills/auditing-pyasn1/scripts/check_pyasn1_facts.py
   ```

   It prints each claim with what it measured, and exits 0 only if all claims hold. `references/output-pyasn1-0.6.5.txt`
   and `references/output-pyasn1-0.6.4.txt` are the recorded results for those pyasn1 versions. Run the script when
   your version is another one. A claim that fails means a rule below is out of date: correct the rule.

## Quick workflow

1. Find the helper and all its callers before you change its behavior.
2. Reuse the helpers that the profile names.
3. Go through the pattern checklist for every changed line that touches an ASN.1 object.
4. Check every time value against the rule for times.
5. Test the DER encoding and decoding, and read the structure with another implementation where the profile says so.

## Rules

### 1. Variables: `is None`. Fields: `isValue`. Never truthiness

Never test an ASN.1 object with `if value:` or `if not value:`. A valid object can count as false [25]. An object
without a value counts as false for a SEQUENCE and a CHOICE, and raises `PyAsn1Error` for an INTEGER, an OCTET STRING and a
SEQUENCE OF [29].
`is None` asks whether you hold an object at all. `isValue` asks whether that object carries a value.

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

These values count as false but are valid: `Integer(0)`, `Boolean(False)`, `OctetString(b"")` and an empty
SEQUENCE OF [25]. An absent OPTIONAL field is a schema object: `is None` is false for it, `isValue` is false, and
`bool()` of an absent INTEGER field raises [24].

### 2. DEFAULT fields and SEQUENCEs with only OPTIONAL fields

- A DEFAULT field (for example `cA` in `BasicConstraints`) always has `isValue == True`, also when it was never set
  [27]. Compare its value: `bool(bc["cA"])`.
- A SEQUENCE whose fields are all OPTIONAL (for example `validity` in `CertTemplate`) has `isValue == True` even
  when it is absent [28]. Check its fields: `any(value[name].isValue for name in value)`.

### 3. CHOICE

`getName()` and `getComponent()` of a CHOICE without a component raise `Component not chosen` [32]. Check
`isValue` first.

### 4. Reading and encoding fields

- `obj["field"]` and `getComponentByName("field")` return the same object [33]. Use the subscript. Keep the method
  when you need an argument such as `instantiate=False`.
- A field that is set but empty has `isValue == False` and is still encoded. `getComponentByName(name,
  instantiate=False)` reads it as `noValue` [22]. So `isValue == False` does not prove that the field is absent
  from the DER. Encode and look at the bytes.
- The encoder leaves out an OPTIONAL SEQUENCE that has no field set. `encoder.encode(value, omitEmptyOptionals=False)`
  writes it as an empty element, for example an absent `validity` of a `CertTemplate` as `a400` [23].

### 5. `.clone()` does not make an exact copy

`clone()` of a SEQUENCE or a SEQUENCE OF makes a new object with the type and the tags and no content.
`clone()` of a single value, without arguments, returns the same object.

- A SEQUENCE: `clone()` has the type and the tags, and no fields. This holds untagged [7], with an IMPLICIT tag [10]
  and with an EXPLICIT tag [13]. Whether the clone can be encoded depends on the fields. The clone of an
  `AlgorithmIdentifier` raises, because the field `algorithm` is required [7]. The clone of a `CertTemplate` (all
  fields OPTIONAL), of `BasicConstraints` (DEFAULT and OPTIONAL fields) and of a `CertRepMessage` (a required
  SEQUENCE OF) encodes as an empty SEQUENCE without an error, so the fields are lost without a sign [42] (rule 2
  [28]). Never encode a `clone()`.
- A SEQUENCE OF: the clone of one without a SIZE constraint (`RDNSequence`) encodes as an empty SEQUENCE OF [42]. With
  a SIZE constraint (`Extensions`, `GeneralNames`) the encoder raises [42].
- `clone(cloneValueFlag=True)` of an `AlgorithmIdentifier` is a new object with the same DER [8] [11] [14]. It clones
  the constructed components again [40] and shares only the simple components, such as the OID `algorithm`:
  `clone["algorithm"] is value["algorithm"]` [9] [12] [15]. An assignment to the clone replaces a component in the
  clone, and the original keeps its value [40].
- `clone(cloneValueFlag=True)` raises `PyAsn1Error` for many filled structures: every holder of a Name (an
  `RDNSequence` that holds an RDN, also with an IMPLICIT or EXPLICIT tag [38], a `GeneralName` with `directoryName`,
  a `TBSCertificate` and a `Certificate` [39]), a `PKIStatusInfo` with `statusString` and a `CertRequest` with
  `controls` [43]. Never use it as a copy.
- A single value such as NULL, INTEGER or OCTET STRING: `clone()` without arguments returns the same object, not a
  copy [1] [3] [5] [45]. `clone(value)` returns a new object with the same type and tags [2] [4] [6] [45].
- The clone of a field of a structure keeps the tag of the field. The clone of `directoryName` ([4] EXPLICIT)
  encodes as `a4...`, and a new `rfc5280.Name` has no tag [16]. Assigning an untagged `Name` to the field raises
  `KeyError` (tag-incompatible) [17]. A cloned or a decoded `PKIFreeText` assigned to `statusString` raises `KeyError`
  too [44]. Fill the components of the field instead.
- A new, empty SEQUENCE OF in a field encodes, but `clone(cloneValueFlag=True)` of that field raises [18].
- `copy.deepcopy` works for INTEGER and NULL values [19]. It raises `PyAsn1Error` for an `AlgorithmIdentifier` and for
  a SEQUENCE OF [20]. Do not use it for a structure.
- `copy.copy` of a SEQUENCE has the same DER and is no copy: it shares the component list, so an assignment to a field
  of the copy changes the original [21] [41]. Never use it as a copy.
- For a copy that shares nothing, decode the DER of the object with a clone of it as the spec:
  `decoder.decode(encoder.encode(value), asn1Spec=value.clone())` [30]. It works for a SEQUENCE and a SEQUENCE OF,
  untagged, IMPLICIT and EXPLICIT, and for a filled Name. Use it as the copy of a structure.

### 6. BIT STRING and OCTET STRING

- `.asOctets()` returns the bytes of an OCTET STRING. `str()` returns a text and `prettyPrint()` a hex text [34].
- Not for named bits such as keyUsage: `BitString("101").asOctets()` is `05`, but the DER is `030205a0`: the
  unused-bits octet `05`, then the bits `a0` [26]. The profile names the helper for named bits.
- Two values with different tags compare equal as objects, and their DER differs [35]. Compare the DER.

### 7. Bytes after the structure

`decoder.decode` returns the bytes after the structure as `rest` and raises no error [31]. Reject a non-empty
`rest`, or use a helper of the repository that does it (see the profile).

### 8. Times

- Give `GeneralizedTime.fromDateTime` a datetime in UTC with whole seconds. It writes microseconds as a fraction
  [36]. A datetime with an offset gives `+HHMM`, and the DER encoder refuses it. A datetime without a time zone
  gives `Z`, as if it were UTC [37]. `replace(microsecond=0)` removes the fraction. Convert with
  `astimezone(timezone.utc)` first.
- The DER encoder of pyasn1 accepts a fraction [36]. A test has to check for it.
- Which form is valid depends on the structure. RFC 5280 asks for certificates (Section 4.1.2.5.2) and CRLs
  (Section 5.1.2.4): GeneralizedTime in UTC with `Z`, with seconds, without a fraction. For any other structure the
  profile of its protocol decides; the profile of the repository names the ones in use.

### 9. pyasn1-alt-modules first

When a referenced RFC type exists in `pyasn1-alt-modules`, import it and its constants instead of writing a local
class or a literal OID. Define a local structure only when no suitable type exists, and name the RFC it comes from.

### 10. Tests

When you add or change a builder or a parser:

- test the positive and the negative path, and malformed input;
- test DER encoding and decoding of the value, and that the tags are right for every supported combination;
- test the absent field, the present but empty field and a `None` argument explicitly;
- test that a time has no fraction where the structure forbids it;
- a round trip through your own encoder and decoder proves only that they agree. The profile names what else a
  builder is read by, and what is read back.

## Pattern checklist

| Use | Instead of | Reason | Claim |
|---|---|---|---|
| `if obj is None:` for a variable or argument | `if not obj:` | an empty or zero object counts as false | [25] |
| `obj["field"].isValue` | `obj["field"] is None`, `if obj["field"]:` | an absent field is a schema object; `bool()` of it raises | [24] |
| `isValue` before `getName()` or `getComponent()` of a CHOICE | reading it directly | an unset CHOICE raises `Component not chosen` | [32] |
| `bool(bc["cA"])` for a DEFAULT field | `bc["cA"].isValue` | a DEFAULT field always has a value | [27] |
| a check of its fields for a SEQUENCE with only OPTIONAL fields | `isValue` of the SEQUENCE | it is true when nothing is set | [28] |
| `obj["field"]` | `getComponentByName("field")` | same object, easier to read; keep the method if you need `instantiate=False` | [33] [22] |
| `.asOctets()` | `str()`, `prettyPrint()` | only it returns the bytes | [34] |
| the named-bit helper of the profile | `.asOctets()` for named bits | the bytes differ from the DER content | [26] |
| a decode that rejects a non-empty `rest` | ignoring `rest` | the decoder accepts bytes after the structure | [31] |
| a decode of the DER with `value.clone()` as the spec for a copy of a structure | `clone()`, `clone(cloneValueFlag=True)`, `copy.copy`, `copy.deepcopy` | `clone()` has no fields and may encode as an empty SEQUENCE; `clone(cloneValueFlag=True)` raises for a filled Name, a `statusString` and `controls`; `copy.copy` shares the component list; deepcopy raises | [7] [42] [38] [43] [41] [20] [30] |
| the components of the tagged field filled one by one | an untagged, cloned or decoded object of the same type assigned to the field | the assignment raises `KeyError` | [17] [44] |
| `clone(new_value)` for a new single value | `clone()` as a copy of a single value | `clone()` returns the same object | [1] [2] [45] |
| a datetime in UTC with whole seconds | `datetime.now()` directly, a datetime with an offset | a fraction or `+HHMM` is written | [36] [37] |
| the DER of two values compared | the objects compared | the tags show only in the DER | [35] |
| types and OIDs from `pyasn1-alt-modules` | local classes, literal OIDs | one definition | none |

## Files in this skill

- `SKILL.md` - the rules, the pattern checklist and the completion checklist.
- `profiles/cmp-test-suite.md` - what is specific to the cmp-test-suite.
- `scripts/check_pyasn1_facts.py` - the claims, measured with the installed pyasn1.
- `references/output-pyasn1-0.6.5.txt`, `references/output-pyasn1-0.6.4.txt` - the recorded results of the script.
- `agents/openai.yaml` - discovery metadata.
- `.tags` - index tags.

## Completion checklist

- [ ] The profile of the repository was read.
- [ ] The pattern checklist was applied to every changed line.
- [ ] Variables and arguments use `is None`, fields use `isValue`, nothing uses truthiness.
- [ ] Nothing uses `clone()`, `copy` or `deepcopy` as an exact copy of a structure.
- [ ] BIT STRING and OCTET STRING values are read as the rules say; named bits use the helper of the profile.
- [ ] Bytes after a decoded structure are rejected.
- [ ] Time values are in UTC, with whole seconds where the structure asks for it.
- [ ] pyasn1-alt-modules is used where possible.
- [ ] The tests cover DER encoding and decoding, the tags, absent and empty fields, and malformed input.
- [ ] The tests of the repository pass.
