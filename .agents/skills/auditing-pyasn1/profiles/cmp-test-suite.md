# Profile: cmp-test-suite

Use this with `SKILL.md` in the cmp-test-suite repository. The code is in `resources/` and `pq_logic/`. Commands run
from the repository root with `.venv/bin/python`, the environment that `uv sync` creates.

## Helpers to reuse

`resources/asn1utils.py`:

- Read a value: `get_asn1_value(obj, query)`, `get_asn1_value_as_string`, `get_asn1_value_as_number`,
  `get_asn1_value_as_bytes`, `get_asn1_value_as_datetime`, `get_asn1_value_as_der`. The query is a path such as
  `header.sender.directoryName.rdnSequence/0`. Use them instead of new path logic, also for BIT STRING and OCTET
  STRING values.
- Named bits: `get_set_bitstring_names(bitstring)` returns the names of the set bits as one text, for example
  `"digitalSignature, keyEncipherment"`. To test a set of bits, compare it with the expected names. Do not use
  `is_bit_set(bitstring, "a,b", exclusive=...)` for that: with `exclusive=False` it is true if any one of the listed
  bits is set, and with `exclusive=True` it is true if one listed bit is the only bit set, or if the set bits are
  the listed ones, in the order of the named bits, with no space after the comma. It raises `ValueError` if every
  named bit is set (measured on a KeyUsage). `asn1_names_to_bitstring(type, "a,b")` builds the BIT STRING.
- Decode: `try_decode_pyasn1(data, asn1_spec)` returns `(decoded, rest)` like the pyasn1 decoder and raises
  `BadAsn1Data` if decoding fails. It does not refuse bytes after the structure: reject a non-empty `rest` yourself
  [31].
- Encode: `encode_to_der(structure)` is `encoder.encode`, in DER.

`resources/prepareutils.py`: `prepare_generalized_time(date=None)` and `prepare_utc_time(date=None)`. Both call
`_prepare_date_time_object`, which reads `None` as now in UTC, a `str` with `DateTime.convert_date`, a `float`
with `datetime.fromtimestamp` and a `datetime` as it is, and ends with `replace(microsecond=0)`.

## Times

`_prepare_date_time_object` removes the fraction, so a `GeneralizedTime` from it has whole seconds [36]. It does
not convert to UTC. Measured with `TZ=Europe/Berlin`:

- a `datetime` with the offset +02:00 gives `20260102030405+0200`, which the DER encoder refuses [37];
- the `float` 1767319445.9 is 02:04:05 UTC, and gives `20260102030405Z`: the local time with a `Z`.

So pass `None` or a `datetime` in UTC, and do not pass a `float`.

## Tests

- The unit tests are the files `test_*.py` below `unit_tests/`. The tests of `prepare_*` builders are the files
  `test_prepare_*.py`, for example `unit_tests/tests_prepare_cert_related_structures/test_prepare_cert_status.py`.
  Find them with `find unit_tests -name 'test_prepare_*.py'`.
- `unit_tests/test_pyasn1_assumption.py` holds the tests of the repository about pyasn1 behaviour. A new claim of
  this skill does not belong there: it belongs in `scripts/check_pyasn1_facts.py`.
- Run all tests with `make unittest`. Run one file with
  `PYTHONPATH=./resources .venv/bin/python -m pytest unit_tests/tests_prepare_cert_related_structures/test_prepare_cert_status.py`.
- The round trip is `encoder.encode`, then `decoder.decode(..., asn1Spec=...)`, then `rest == b""`. The skill
  `prepare-asn1-structure-unit-tests`, if installed, has the checker for it.
- Lint and checks: `make verify` (reuse, ruff, pylint, pyright, codespell).
