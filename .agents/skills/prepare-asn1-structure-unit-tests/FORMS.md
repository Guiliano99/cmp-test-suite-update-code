# Draft form for ASN.1 builder tests

Use this form before you write or update a test file.

## Scenario form

- Target function:
- Owning module:
- Target test file:
- Type to decode into (the spec):
- Required fields to assert:
- Invalid input to cover:
- Other implementation that reads the result (profile):

## Round-trip test, pyasn1 decoder

```python
def test_prepare_<name>_encoding_decoding(self):
    """
    GIVEN valid inputs for the builder.
    WHEN the structure is DER-encoded and decoded.
    THEN the decoded structure has the expected fields and no bytes remain.
    """
    structure = prepare_<name>(...)
    der_data = encoder.encode(structure)
    decoded, rest = decoder.decode(der_data, asn1Spec=<Type>())

    self.assertEqual(rest, b"")
    self.assertTrue(decoded["<field>"].isValue)
```

## Round-trip test, decode_der

```python
def test_prepare_<name>_encoding_decoding(self):
    """
    GIVEN valid inputs for the builder.
    WHEN the structure is DER-encoded and decoded with decode_der.
    THEN the decoded structure has the expected fields and encodes to the same bytes.
    """
    der_data = encode_to_der(prepare_<name>(...))
    decoded = decode_der(der_data, <Type>())

    self.assertTrue(decoded["<field>"].isValue)
    self.assertEqual(encode_to_der(decoded), der_data)
```

## Negative-path test

```python
def test_prepare_<name>_invalid_input(self):
    """
    GIVEN invalid input for the builder.
    WHEN prepare_<name> is called.
    THEN an exception is raised.
    """
    with self.assertRaises(ValueError):
        prepare_<name>(...)
```

## Checklist

- Import `encoder` and `decoder` from `pyasn1.codec.der`, or `encode_to_der` and `decode_der`.
- Decode with an explicit spec.
- Assert `rest == b""` after `decoder.decode`.
- Assert the key fields after the decode; use `isValue` for a field, not truthiness.
- Include a negative-path test.
- Read the result with the other implementation that the profile names.
