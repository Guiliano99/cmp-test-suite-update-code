# Reference

## Locate related tests and builders

```bash
grep -Rsn "def prepare_" resources pq_logic
find unit_tests -type f -name 'test_prepare_*.py' | sort
```

## Validate required round-trip pattern

Run checker on one file:

```bash
python3 .github/skills/asn1-skills/prepare-asn1-structure-unit-tests/scripts/check_prepare_asn1_roundtrip.py unit_tests/tests_prepare_cert_related_structures/test_prepare_cert_status.py
```

Run checker on one suite:

```bash
python3 .github/skills/asn1-skills/prepare-asn1-structure-unit-tests/scripts/check_prepare_asn1_roundtrip.py unit_tests/tests_prepare_cert_related_structures
```

## Run unit tests

Run one file:

```bash
python3 -m unittest discover -s unit_tests/tests_prepare_cert_related_structures -p 'test_prepare_cert_status.py'
```

Run one suite:

```bash
python3 -m unittest discover -s unit_tests/tests_prepare_cert_related_structures -p 'test_prepare_*.py'
```

Run all tests:

```bash
python3 -m unittest discover -s unit_tests -p 'test_*.py'
```
