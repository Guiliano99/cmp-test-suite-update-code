# Prepare ASN.1 Unit Test Draft Form

Use this form before writing or updating a test file.

## Scenario form

- Target function: `prepare_...`
- Owning module:
- Target test file:
- Expected ASN.1 type after decode (`asn1Spec`):
- Required fields to assert:
- Invalid input case to cover:

## Required round-trip test template

```python
def test_prepare_<name>_encoding_decoding(self):
    """
    GIVEN valid inputs for the prepare function.
    WHEN the returned ASN.1 structure is DER-encoded and decoded.
    THEN the decoded structure matches expectations and has no remaining bytes.
    """
    structure = prepare_<name>(...)
    der_data = encoder.encode(structure)
    decoded, rest = decoder.decode(der_data, asn1Spec=<ExpectedType>())

    self.assertEqual(rest, b"")
    self.assertTrue(decoded["<field>"].isValue)
```

## Negative-path template

```python
def test_prepare_<name>_invalid_input(self):
    """
    GIVEN invalid input for the prepare function.
    WHEN prepare_<name> is called.
    THEN an exception is raised.
    """
    with self.assertRaises(ValueError):
        prepare_<name>(...)
```

## Checklist

- Import both `encoder` and `decoder` from `pyasn1.codec.der`.
- Include at least one encode/decode round-trip test in each new `test_prepare_*.py`.
- Decode with explicit `asn1Spec=...`.
- Assert `rest == b""`.
- Assert key structure fields after decode.
- Include at least one negative-path test.
