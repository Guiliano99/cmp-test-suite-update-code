# Profile: cmp-test-suite

Use this with `SKILL.md` in the cmp-test-suite repository. Commands run from the repository root with
`.venv/bin/python`, the environment that `uv sync` creates.

## Where things are

- Builders: the `prepare_*` functions in `resources/` and `pq_logic/`. Find them with
  `grep -Rsn "def prepare_" resources pq_logic`.
- Tests: `unit_tests/tests_*/test_prepare_*.py`. Find the test file of a builder with
  `find unit_tests -type f -name 'test_prepare_*.py' | sort`, and put a new one in the folder of its neighbors.
- Calls a test uses: `encoder.encode` and `decoder.decode(..., asn1Spec=...)` from `pyasn1.codec.der`;
  `encode_to_der` and `try_decode_pyasn1` from `resources/asn1utils.py` (`try_decode_pyasn1` returns
  `(decoded, rest)` like the decoder); `try_encode_pyasn1` from `unit_tests/utils_for_test.py`. The checker knows
  them all. This repository has no `decode_der`.
- Style of a test: GIVEN/WHEN/THEN in the docstring, a `unittest.TestCase` class.

## Commands

Checker on one file, and on all builder tests:

```bash
.venv/bin/python .agents/skills/prepare-asn1-structure-unit-tests/scripts/check_prepare_asn1_roundtrip.py unit_tests/tests_prepare_cert_related_structures/test_prepare_cert_status.py
.venv/bin/python .agents/skills/prepare-asn1-structure-unit-tests/scripts/check_prepare_asn1_roundtrip.py unit_tests
```

On the commit e409ea82 the second command reports 22 of the 43 `test_prepare_*.py` files. Some of them do the round
trip in a helper function that the checker does not follow; the others have none.

Tests:

```bash
PYTHONPATH=./resources .venv/bin/python -m pytest unit_tests/tests_prepare_cert_related_structures/test_prepare_cert_status.py
make unittest
```

`make unittest` runs the whole suite in parallel. `make verify` runs reuse, ruff, pylint, pyright and codespell.

## Other implementations

This repository asks for none in a unit test: the round trip is the rule. The suite is checked against a CA when it
runs, for example `make test env=mock_ca` (see `SETUP.md`).

## Example

A round-trip test of the repository, `unit_tests/tests_prepare_cert_related_structures/test_prepare_cert_status.py`:

```python
def test_prepare_certstatus_encoding_decoding(self):
    """
    GIVEN a `CertStatus` prepared with a valid certificate hash and request ID.
    WHEN the `CertStatus` is encoded to DER and then decoded.
    THEN the decoded values should match the original certificate hash and request ID,
    with no leftover data after decoding.
    """
    cert_status = prepare_certstatus(
        cert_hash=self.cert_hash, cert_req_id=self.cert_req_id, status=self.valid_status
    )
    encoded_cert_status = encoder.encode(cert_status)
    decoded_cert_status, rest = decoder.decode(encoded_cert_status, asn1Spec=rfc9480.CertStatus())
    self.assertEqual(rest, b"")
    self.assertEqual(decoded_cert_status["certHash"], univ.OctetString(self.cert_hash))
    self.assertEqual(decoded_cert_status["certReqId"], self.cert_req_id)
```

A negative-path test, `test_prepare_popo.py`:

```python
def test_prepare_pop_invalid_without_private_key_or_alg_oid(self):
    """
    GIVEN a signature without a private key or algorithm OID.
    WHEN prepare_pop is called without private_key and alg_oid.
    THEN it should raise a ValueError.
    """
    with self.assertRaises(ValueError):
        prepare_popo(signature=self.signature, signing_key=None, alg_oid=None)
```
