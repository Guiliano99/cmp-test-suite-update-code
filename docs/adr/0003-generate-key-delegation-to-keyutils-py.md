<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# Delegate PQ/hybrid key generation to keyutils-py — first migration slice, on hold

Status: proposed (implemented, gate-tested, found to be a regression; reverted to a saved patch, held for package-side fixes)

## Context

The host generates all keys through one function, `generate_key` in `resources/keyutils.py`,
exposed to Robot Framework as the `Generate Key` keyword (59 RF call sites, ~333 unit-test call
sites, plus imports from `mock_ca/`, `pq_logic/`, and `resources/`). `keyutils-py`
(Guiliano99/keyutils-py, branch `ImproveQuality`) is a standalone extraction of the same key
logic and is the long-term home for it. The goal was a gradual migration: replace the local
`generate_key` with the package's, verifying the suite still works with liboqs (latest stable
OQS C 0.16.0) and without it.

A literal replacement was rejected by the facts: the package `generate_key`
(`algorithm="hss", **params`) is PQ/hybrid-only (traditional names raise
`NotImplementedError`), dropped `seed=`, and returns package wrapper classes that are a
distinct hierarchy from the host's `pq_logic.keys` (838 of 864 lines of
`pq_logic/keys/sig_keys.py` are copied verbatim into `keyutils_py/keys/sig_keys.py`, but
`isinstance(keyutils_py.generate_key("ml-dsa-44"), pq_logic.keys.sig_keys.MLDSAPrivateKey)`
is `False`). The thin slice therefore keeps the local function as the public entry point (RF
keyword, unchanged signature, unchanged traditional + `seed=` behaviour) and delegates only the
PQ/hybrid by-name branch, gated by the package's own predicates
(`is_hybrid_algorithm` / `is_supported_pq_algorithm`), so names the package does not cover
(e.g. `rsa-kem`) keep the local factory path.

## Decision

- Add `keyutils-py` as a hard dependency pinned by commit hash (`ed9da3a`); the
  `ImproveQuality` branch has no tags/releases.
- Delegate only the PQ/hybrid by-name branch; traditional keys, `seed=`, and
  `from_keys`-style hybrid assembly stay local. No fallback from the delegated path back to
  the local factory, so package gaps surface instead of being masked.
- No `mock_ca/` changes for this migration; package-side deficiencies are reported to the
  `keyutils-py` maintainers (see `docs/keyutils-py-integration-report.md`) instead of being
  patched around in the host.
- Move the `pq` dependency from the unpinned liboqs-python fork to
  `liboqs-python==0.16.0.1` (official, OQS C 0.16.0) so the C version is reproducible; gates
  set `OQS_INSTALL_PATH` explicitly to avoid a stale `$HOME/_oqs` build.
- Acceptance gates: unit tests with and without liboqs (baseline-diff criterion, i.e. zero new
  failures versus the pre-change state), Robot Framework `tests/` and
  `tests_pq_and_hybrid/` (non-verbose) against a live CA with liboqs present, plus lint.

## Gate results (2026-10-21, worktree branch `MigrateGenerateKey`)

| Gate | Baseline (pre-change) | Post-delegation | Verdict |
|---|---|---|---|
| Unit tests, no liboqs | 1136 passed / 39 failed / 11 errors | 979 passed / 221 failed / 41 errors | **157 new failures** |
| Unit tests, liboqs 0.16 | 1191 passed / 0 failed / 4 errors | 1024 passed / 188 failed / 34 errors | **167 new failures** |
| RF `tests/` (live cloudpki CA) | 255: 3 passed / 185 failed / 67 skipped | not re-run | blocked by live-CA outage (see below) |
| RF `tests_pq_and_hybrid/` (live cloudpki CA) | 153: 0 passed / 142 failed / 11 skipped | not re-run | blocked by live-CA outage (see below) |

The new failures are attributable to the delegation, with two verified mechanisms:

1. **Class identity.** Host code dispatches on `pq_logic.keys` wrapper classes
   (`ensure_is_sign_key` and dozens of `isinstance` checks). Every delegated key fails those
   checks; the dominant new error is
   `the provided key is not allowed to be used for signing: <class 'keyutils_py.keys.composite_sig.CompositeSigPrivateKey'>`
   (50 occurrences), plus XMSS/HSS/ML-DSA package classes, breaking `CAHandler` construction
   (all mock-ca tests), composite/sun-hybrid, and key-loading test groups.
2. **No-liboqs contract change.** The local factory has a pure-Python fallback for some PQ
   algorithms (FrodoKEM via `pq_logic/fips/frodokem.py`, ML-DSA, ...), so e.g.
   `TestFrodoKEM` passed in the no-liboqs baseline. The delegated path has no fallback and
   raises `keyutils_py.exceptions.MissingOQSDependencyError` (72 occurrences in the no-liboqs
   run). It is an `ImportError` subclass, so `assertRaises(ImportError)`-style tests keep
   passing, but direct key-generation tests now fail.

Both mechanisms are package-side design issues (single source of truth for the wrapper
classes; documented no-OQS contract), not host bugs. The slice is therefore **not safe to
merge as-is**; the delegation is preserved in
`docs/keyutils-py-delegation.patch` and re-applied once the package addresses
`K1` (class identity) in the integration report. K2 (FrodoKEM bitstring-5) was fixed in the
package (FixKeyutilsPqIntegration @ b52ef22) and K3 (XMSS name aliasing) was invalidated on
re-verification (the host uses the package's canonical names), so K1 is the only remaining
package-side blocker.

Separately, the live `cloudpki` CA was broken during the trial window: every RF suite failed
in setup because the CA rejected the initial registration with
`"upstream exchange: exception processing request at upstream interface for first bodyType 0"`
(reproduced directly with the repo's own helpers; a garbage POST is handled correctly by the
front end, proving the gateway is healthy). That outage blocks meaningful live RF runs
independent of this change; re-run `make test env=cloudpki` and
`make test-pq-hybrid env=cloudpki` on the re-pin commit and again on the delegation commit
once the CA is healthy.

## Consequences

- The `pq` extra is now a pinned official release (host and package, b52ef22), and the
  FrodoKEM implementation is adapted to bitstring 5 in the host and in the package
  (report K2, fixed in b52ef22).
- OQS C 0.16.0 removed SPHINCS+ (upstream change, report K7 — SLH-DSA itself is unaffected);
  host RF tests that reference SPHINCS+ cannot pass on any 0.16.0-based configuration and need
  host-side test adaptation.
- Until K1 (class identity) is resolved in the package, no further delegation is possible:
  every call path that `isinstance`s on the host wrapper classes is exposed.
