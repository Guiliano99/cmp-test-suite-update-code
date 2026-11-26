---
name: rf-cmp-test-case-auth
description: >-
  Author or update Robot Framework CMP test cases for authentication,
  authorization, and protection-related behavior in the cmp-test-suite
  codebase. Use when adding or revising RFC-driven CMP tests for sender and
  recipient validation, MAC protection, signature protection, unauthorized
  senders, invalid or duplicate protected requests, PKIStatus handling, and
  failInfo assertions. Applies to the cmp-test-suite only.
---

# RF CMP Test Case Authoring: Auth and Protection

Use this skill when changing Robot Framework CMP tests that exercise authentication or message protection behavior.
Prefer existing keywords and helpers over adding new CMP logic. Commands run from the repository root with
`.venv/bin/python`, the environment that `uv sync` creates.

## Files in this skill

- `SKILL.md` - skill definition and workflow guidance.
- `agents/openai.yaml` - display metadata for skill discovery.
- `.tags` - discovery tags for repository indexing.

## Quick workflow

1. Choose the owning suite:
   - General CMP behavior: `tests/basic.robot`, `tests/lwcmp.robot`.
   - MAC protection: `tests/mac_alg_pki_prot_tests.robot`.
   - Signature protection: `tests/trad_alg_pki_prot_tests.robot`.
   - PQ and hybrid protection: `tests_pq_and_hybrid/pq_sig_pkiprotection.robot`.
2. Search existing keywords before you write new ones:
   - `resources/keywords.resource`
   - `resources/protectionutils.py`
   - `resources/checkutils.py`
   - `resources/cmputils.py`
   - `resources/certbuildutils.py`
3. Check whether a generator writes the test cases you change. `scripts/generate_pki_prot_tests.py` writes
   PKIProtection test cases; change the generator, not only the `.robot` file.
4. Add or modify the test case with:
   - a descriptive test case name
   - `[Documentation]`
   - `[Tags]` from the table below
   - explicit assertions
   - RFC section or errata references in the documentation
5. Keep tests deterministic: use existing key and certificate fixtures, avoid hidden state and implicit global
   variables, and reuse established protection patterns.
6. Update the generated documentation when the coverage changes: `make docs`, and `make unittest` for the Python
   code.
7. Run the relevant Robot suites.
8. Check the source files:
   - `.venv/bin/ruff check resources/`
   - `.venv/bin/robocop check <changed .robot and .resource files>`

## Test case requirements

Every auth or protection test has:

- `[Documentation]` with the expected CMP behavior.
- `[Tags]` for the result (`positive` or `negative`), the execution class, the message type, the protection and the
  RFC traceability.
- explicit status and failInfo assertions.
- deterministic nonce, password and certificate handling.
- no duplicated keyword names in the same source file.

## Common assertion patterns

Keywords from `resources/keywords.resource` and `resources/checkutils.py`, as the tests use them:

- `PKIMessage Body Type Must Be    ${response}    error`
- `PKIMessage Body Type Must Be    ${response}    ip`
- `PKIStatus Must Be    ${response}    rejection`
- `PKIStatus Must Be    ${response}    accepted`
- `PKIStatusInfo failinfo Bit Must Be    ${response}    failinfo=notAuthorized    exclusive=True`
- `PKIStatusInfo failinfo Bit Must Be    ${response}    failinfo=badRequest,wrongIntegrity    exclusive=True`
- `Validate Sender And Recipient Nonce    ${response}    ${request}`
- `Sender And Recipient Nonces Must Match    ${request}    ${response}`
- `SenderNonce Must Be At Least 128 Bits Long    ${response}`
- `Certificate Must Be Valid    ${cert}`

## Tags

These are the tags that tests carry, counted with `robot.api.TestSuiteBuilder` over `tests/`,
`tests_pq_and_hybrid/` and `tests_mock_ca/` on the commit e409ea82: 1932 tests. Robot Framework matches a tag
without regard to case and underscores, so `--include pkiprotection` selects `PKIProtection`, and `transactionID` and
`transactionId` are one tag. `CONTRIBUTING.md`, "Using tags", describes more tags.

| Tag | Tests | Meaning |
|---|---|---|
| `positive` | 518 | the CA has to accept |
| `negative` | 1323 | the CA has to reject |
| `minimal` | 81 | default coverage |
| `verbose-tests` | 1484 | exhaustive or multi-configuration tests |
| `protection` | 118 | protection of a message |
| `PKIProtection` | 308 | the protection algorithm of the PKIMessage, PQ and hybrid suites |
| `pki-protection` | 48 | the protection algorithm of the PKIMessage, traditional signatures |
| `added-protection` | 176 | added protection of a nested message (RFC 9483 Section 5.2.2.1); `adding-protection` of `CONTRIBUTING.md` is on 6 tests |
| `mac` | 134 | MAC-based protection |
| `hmac` | 54 | HMAC-based protection |
| `pbm` | 18 | PasswordBasedMac |
| `pbmac1` | 18 | PBMAC1 |
| `signature` | 9 | signature-based protection |
| `rfc9483-header` | 462 | the `PKIHeader` rules of RFC 9483 |
| `rfc9483-validation` | 562 | the validation rules of RFC 9483 |
| `verbose-pkiheader` | 429 | generated `PKIHeader` tests |
| `PKIHeader` | 38 | the `PKIHeader` field |
| `sender` | 61 | the `sender` field |
| `senderKID` | 33 | the `senderKID` field |
| `senderNonce` | 61 | the `senderNonce` field |
| `recipNonce` | 20 | the `recipNonce` field |
| `transactionID` | 59 | the `transactionID` field |
| `extraCerts` | 38 | the `extraCerts` field |
| `popo` | 35 | proof of possession |
| `badPOP` | 22 | the failInfo `badPOP` |
| `bad_message_check` | 40 | the failInfo `badMessageCheck` |
| `multiple-auth` | 9 | several authentications in one request |
| `ir`, `cr`, `p10cr`, `kur`, `ccr`, `rr`, `genm`, `certConf`, `csr` | 197, 92, 176, 95, 90, 24, 30, 106, 12 | the message type |
| `mock-ca` | 40 | tests for the Mock CA (`tests_mock_ca/`) |

`crypto` (3 tests), `status` (2) and `rfc6712` (1) are used too.

To count again:

```bash
.venv/bin/python - <<'PY'
import collections
from robot.api import TestSuiteBuilder
from robot.utils import normalize

count = collections.Counter()
def walk(suite):
    for test in suite.tests:
        count.update({normalize(str(tag), ignore="_") for tag in test.tags})
    for child in suite.suites:
        walk(child)
for folder in ("tests", "tests_pq_and_hybrid", "tests_mock_ca"):
    walk(TestSuiteBuilder().build(folder))
print(count.most_common())
PY
```

Use `minimal` for good default coverage and `verbose-tests` for exhaustive tests.

## Proposing new tags

Introduce a new tag only when it is a stable and useful selection dimension, and no tag above or in
`CONTRIBUTING.md` describes the concept. When you add one:

1. Apply it to the new and the affected tests.
2. Document its meaning in the "Using tags" table of `CONTRIBUTING.md`, and in `SERVER_TEST_COVERAGE.md` where it
   changes what is covered.
3. Check that the selection works without running against a server:
   `.venv/bin/python -m robot --dryrun --include <new-tag> --output NONE --log NONE --report NONE <suite file>`.
4. Regenerate the documentation with `make docs`.
5. Change the generator in `scripts/` if it writes the tests that carry the tag.
6. Run `.venv/bin/robocop check` on the changed files.

## Completion checklist

- [ ] The test case has a descriptive name.
- [ ] `[Documentation]` and `[Tags]` are present, and the tags are ones that tests carry.
- [ ] Existing keywords and helpers are reused.
- [ ] Assertions are explicit and deterministic.
- [ ] RFC or errata references are documented.
- [ ] The targeted Robot suites pass.
- [ ] The unit tests pass (`make unittest`).
- [ ] The documentation is regenerated when it is relevant (`make docs`).
- [ ] The source files pass `ruff` and `robocop`.
