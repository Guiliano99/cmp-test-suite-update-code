# Dependency update workflow

How to update a dependency in this repository and prove the suite still works. Developed during
the keyutils-py / liboqs-python / bitstring / pycryptodome integration (see
`docs/adr/0003-generate-key-delegation-to-keyutils-py.md` and
`docs/keyutils-py-integration-report.md`).

## When this applies

Any change to a version pin in `pyproject.toml` (direct dependency, optional extra, or
git/URL source), or adding a new direct dependency. It also applies when a transitive dependency
of a pinned package breaks the build (e.g. a package's own pins conflict with the repo's pins).

## Procedure

1. **Branch.** Work on a dedicated branch (CamelCase: `UpdateBitstring5`, `PinLiboqs016`). Never
   update a dependency and change unrelated code in the same commit.
2. **Isolate.** For risky or long trials use a worktree off `main` so the main checkout and its
   venv are untouched:
   `git worktree add /home/debian/worktrees/<name> -b <Branch> main`
3. **Read the upstream release notes first.** Record, before touching anything:
   - removed/renamed APIs and mechanisms (for OQS: SPHINCS+ removed in 0.16.0, FrodoKEM
     renamed, SLH-DSA underscore naming),
   - breaking changes in dependencies the package itself pins (bitstring 4 -> 5 changed the
     `BitArray` constructor contract AND removed `ConstBitStream`/`.read()` — the pure-Python
     FrodoKEM backend needed four site fixes, and the package's own port had only done one),
   - new minimum/maximum bounds (e.g. `cryptography<51` in keyutils-py).
   When a version jump removes a whole API, grep the repo for every usage of the old API
   (`rg 'ConstBitStream|\.read\('`) — fixing the one call site that the failing test hits and
   stopping there is the classic incomplete port.
4. **Pin the exact thing.** Pinned versions or pinned commits. No unpinned git URLs in
   `pyproject.toml` (the old `liboqs-python @ git+...` without a ref was exactly the class of
   defect this workflow prevents).
5. **Reconcile pins.** Run `uv lock` and read conflicts. If the dependency's own pins conflict
   with the repo's, re-pin on the repo side only if the newer contract is verified to work — and
   record every host-side adaptation (e.g. the bitstring-5 `BitArray.from_zeros` fix in
   `pq_logic/fips/frodokem.py`).
6. **Sync the right environment.** `uv sync` drops optional-extra packages. For the `pq` extra:
   `uv sync --extra pq`. After any sync, verify what is actually installed
   (`uv pip list | grep -i oqs`) and which C library version will load (see step 8).
7. **Baseline before, not after.** Capture the unit-test results on the pre-change commit in
   both configurations (with and without the optional dependency). The acceptance criterion is
   **zero new failures versus the same-config baseline**, not absolute green: without liboqs,
   the liboqs-gated PQ tests that have no local fallback are expected to fail by design.
8. **Environment pins for PQ tests.**
   - `OQS_INSTALL_PATH=<dir>` must be set for every liboqs-dependent run (the default
     `$HOME/_oqs` may hold a stale older build that the wrapper loads silently);
   - fresh C-library build recipe: `OQS_INSTALL_PATH=<empty dir>`, `PYOQS_VERSION=<tag|latest>`
     (default tracks the wrapper version), then `import oqs` once; or build manually with the
     same cmake flags the wrapper uses (see skill `liboqs-fresh-build`);
   - verify the loaded version with `oqs.oqs_version()` and the STFL algorithm table
     (`oqs.StatefulSignature`, not `oqs.Signature`), or read
     `$OQS_INSTALL_PATH/include/oqs/oqsconfig.h`.
9. **Gates, in order.**
   - `PYTHONPATH=./resources .venv/bin/python -m pytest unit_tests -n auto -q` — configuration A
     (without liboqs) and configuration B (`uv sync --extra pq`, with liboqs).
   - Lint: `make verifyformat` (ruff), plus pylint/pyright for changed Python files.
   - Robot Framework live gates (need a healthy live CA, see step 10):
     `PATH="$PWD/.venv/bin:$PATH" OQS_INSTALL_PATH=/opt/oqs-0.16 make test env=cloudpki`
     and `make test-pq-hybrid env=cloudpki` (both already exclude `verbose-tests`).
10. **Check the live CA before blaming the code.** If every RF test fails in suite setup with
    `Parent suite setup failed: The PKIStatus is not as expected. Expected: accepted, Got:
    rejection`, reproduce the setup IR directly (see `resources/keywords.resource`
    `Set Up Test Suite`: `generate_key` -> `build_ir_from_key` -> `protect_pkimessage` -> POST
    `${CA_BASE_URL}`) and read the `PKIStatusInfo`. A healthy front end rejects garbage POSTs
    with a clean 400; an `"upstream exchange: exception ..."` free-text means the CA's own
    upstream interface is broken — that is an external blocker, not a code regression. Do not
    compare an RF run taken in an outage window against a healthy one.
11. **Attribute every new failure.** For each new failure, name the mechanism (class identity,
    exception-type change, missing fallback, missing name alias, upstream API removal) and
    assign it to the package or the host. Package-side deficiencies go into an integration
    report for the package maintainers (do not patch around them in `mock_ca/` or
    `resources/` unless the user approves).
12. **Commit minimally.** One commit per concern: (a) re-pins + required host adaptations,
    (b) the new/changed dependency pin, (c) docs (ADR, workflow, glossary, report). Keep
    subjects compact.
13. **Record.** Update the ADR with measured gate results, store non-obvious environment facts
    (build recipes, env vars, gotchas) in memory/skills, and note anything the next dependency
    update must know.

## Decision rules

- **Zero new failures** versus the same-config baseline is the gate. "Absolute green" is not
  the criterion, and "fewer failures than baseline" is not acceptable without explaining each
  fixed item.
- A dependency that changes a **public contract** (exception types, class identity, supported
  names, optional-dependency behaviour) is not a drop-in update: the integration must be
  boundary-aware (delegate only the paths whose contract matches) and the contract gaps must be
  reported upstream, not worked around.
- If a gate is blocked by an external system (live CA, network), record the blockage with
  evidence and re-run that gate when it is healthy — the other gates still have to pass.
