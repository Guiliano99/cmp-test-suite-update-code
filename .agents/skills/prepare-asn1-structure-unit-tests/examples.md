# Examples for `prepare_*` ASN.1 Unit Tests

Copy and adapt these patterns from existing repository tests.

## Example 1: Required round-trip test

```python
def test_prepare_certstatus_encoding_decoding(self):
    """
    GIVEN a valid cert hash and request id.
    WHEN prepare_certstatus output is encoded and decoded.
    THEN decoding consumes all bytes and expected fields are present.
    """
    cert_status = prepare_certstatus(cert_hash=self.cert_hash, cert_req_id=1234, status="accepted")

    encoded = encoder.encode(cert_status)
    decoded, rest = decoder.decode(encoded, asn1Spec=rfc9480.CertStatus())

    self.assertEqual(rest, b"")
    self.assertTrue(decoded["certHash"].isValue)
    self.assertTrue(decoded["certReqId"].isValue)
```

## Example 2: Round-trip plus semantic assertion

```python
def test_prepare_certreqmsg_with_valid_popo(self):
    """
    GIVEN a private key and common name.
    WHEN prepare_cert_req_msg output is encoded and decoded.
    THEN the decoded structure contains certReq and popo.
    """
    cert_req_msg = prepare_cert_req_msg(private_key=self.private_key, common_name="CN=Hans", cert_req_id=7)
    der_data = encoder.encode(cert_req_msg)
    decoded, rest = decoder.decode(der_data, asn1Spec=rfc4211.CertReqMsg())

    self.assertEqual(rest, b"")
    self.assertTrue(decoded["certReq"].isValue)
    self.assertTrue(decoded["popo"].isValue)
```

## Example 3: Negative-path test

```python
def test_prepare_popo_invalid_without_private_key_or_alg_oid(self):
    """
    GIVEN a signature without private key and algorithm OID.
    WHEN prepare_popo is called.
    THEN ValueError is raised.
    """
    with self.assertRaises(ValueError):
        prepare_popo(signature=b"abc", signing_key=None, alg_oid=None)
```

## Example 4: Minimum imports for ASN.1 prepare tests

```python
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc4211
import unittest
```
