---
name: rf-cmp-test-case-auth
description: >-
  Author or update Robot Framework CMP test cases for authentication,
  authorization, and protection-related behavior in the cmp-test-suite
  codebase. Use when adding or revising RFC-driven CMP tests for sender and
  recipient validation, MAC protection, signature protection, unauthorized
  senders, invalid or duplicate protected requests, PKIStatus handling, and
  failInfo assertions.
---

# RF CMP Test Case Authoring: Auth and Protection

Use this skill when changing Robot Framework CMP tests that exercise
authentication or message protection behavior. Prefer existing keywords and
helpers over adding new CMP logic.

## Files in this skill

- `SKILL.md` - Skill definition and workflow guidance.
- `agents/openai.yaml` - Display metadata for skill discovery.
- `.tags` - Discovery tags for repository indexing.

## Quick workflow

1. Choose the owning suite:
   - General CMP behavior: `tests/basic.robot`, `tests/lwcmp.robot`.
   - MAC/PKI protection: `tests/mac_alg_pki_prot_tests.robot`.
   - Signature/PKI protection: `tests/trad_alg_pki_prot_tests.robot`.
   - PQ/hybrid protection: `tests_pq_and_hybrid/pq_sig_pkiprotection.robot`.
2. Search existing keywords before writing new ones:
   - `resources/keywords.resource`
   - `resources/protectionutils.py`
   - `resources/checkutils.py`
   - `resources/cmputils.py`
   - `resources/certbuildutils.py`
3. Add or modify the test case with:
   - a descriptive test case name
   - `[Documentation]`
   - meaningful `[Tags]`
   - explicit assertions
   - RFC section or errata references in documentation
4. Keep tests deterministic:
   - use existing key/certificate fixtures
   - avoid hidden state and implicit global variables
   - reuse established protection patterns
5. Update documentation artifacts when behavior coverage changes:
   - `make docs`
   - `make unittest`
   - `scripts/check_docs_keyword_duplicates.py` when applicable
6. Run relevant targeted Robot suites.
7. Verify source formatting and linting where applicable:
   - `ruff check resources/`
   - Robocop on changed `.robot` and `.resource` files

## Test case requirements

Every auth or protection test should include:

- `[Documentation]` with the expected CMP behavior.
- `[Tags]` for protocol, protection mechanism, positive/negative result,
  execution profile, and RFC traceability.
- explicit status and failInfo assertions.
- deterministic nonce/password/certificate handling.
- no duplicated keyword names in the same source file.
- no duplicated LibDoc keywords across generated documentation sources when
  documentation changes.

## Common assertion patterns

Use existing patterns such as:

- `PKIMessage Body Type Must Be    ${response}    error`
- `PKIStatus Must Be    ${response}    rejection`
- `PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badAlg,systemFailure    exclusive=True`
- `PKIMessage Body Type Must Be    ${response}    cp`
- `PKIStatus Must Be    ${response}    accepted`
- `Validate Sender And Recipient Nonce    ${response}    ${request}`
- `Sender And Recipient Nonces Must Match    ${request}    ${response}`
- `SenderNonce Must Be At Least 128 Bits Long    ${response}`
- `Certificate Must Be Valid    ${cert}`

## Tags used in this repository

Primary auth/protection tags:

- `auth`
- `unauthorized`
- `negative`
- `positive`
- `crypto`
- `csr`
- `p10cr`
- `mac`
- `signature`
- `protection`
- `failinfo`
- `status`
- `duplicate`
- `pop`
- `minimal`
- `verbose-tests`

Traceability and profile tags:

- `rfc6712`
- `rfc9481`
- `rfc9483`
- `rfc9810`

Use `minimal` for good default coverage and `verbose-tests` for exhaustive or
multi-configuration tests.

## Proposing new tags

Introduce a new tag only when it represents a stable and useful selection
dimension. Good candidates are:

- a protocol message type: `cr`, `ip`, `kur`, `rr`, `genm`
- a protection mechanism: `password-based-mac`, `shared-secret`, `cms`, `external`
- an assertion class: `failinfo`, `status`, `validity`, `nonce`
- an execution class: `minimal`, `verbose`, `experimental`

Before adding a new tag, check whether an existing tag already describes the
concept and whether Robot selection, CI, reports, coverage matrices, or tags
documentation would benefit from it.

## Required actions when adding tags

When a new tag is introduced:

1. Apply it consistently to new and affected tests.
2. Document its meaning in one or more of:
   - relevant test suite documentation comments
   - `SERVER_TEST_COVERAGE.md`
   - `TODO_TESTS.md` if the change relates to planned work
3. Verify Robot selection still works:
   - `robot --include <new-tag> tests/`
   - `robot --exclude <new-tag> tests/`
4. Update generated documentation if tags affect testdoc output.
5. Update generated test matrix scripts or generated tests if the tag or
   algorithm availability affects matrix generation.
6. Run Robocop on changed source files.
7. Update conversion/coverage records if the repository tracks tag counts.
8. Add the tag to this skill's `.tags` when it is useful for discovery.

## Scripts to consider

Relevant files in `scripts/`:

- `scripts/generate_*_tests.py`
- `scripts/generate_alg_test_cases.py`
- `scripts/check_docs_keyword_duplicates.py`
- `scripts/write_stats.py`

Before adding a new script, extend an existing generator or validator when
appropriate. Any new script should use `argparse`, include an SPDX header,
and be documented here and in the Makefile if it becomes part of normal
validation.

## Completion checklist

- [ ] Test case has a descriptive name.
- [ ] `[Documentation]` and `[Tags]` are present.
- [ ] Existing keywords and helpers are reused.
- [ ] Assertions are explicit and deterministic.
- [ ] RFC or errata references are documented.
- [ ] Targeted Robot suites pass.
- [ ] Unit tests pass.
- [ ] Documentation artifacts are regenerated when relevant.
- [ ] Source files pass applicable lint and quality checks.
