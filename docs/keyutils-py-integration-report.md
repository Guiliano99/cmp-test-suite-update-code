<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# keyutils-py (ImproveQuality @ ed9da3a) — Integration Issue Report

Host repo: cmp-test-suite (worktree /home/debian/worktrees/keyutils-migration, branch MigrateGenerateKey on top of main 35ac280b)
Package under test: keyutils-py @ git+https://github.com/Guiliano99/keyutils-py.git@ed9da3a (branch ImproveQuality, commit 2026-10-13)
Host changes TRIED (delegation later reverted, see verdict): re-pin bitstring 4.4.0 -> 5.0.0, pycryptodome 3.23.0 -> 3.24.1, pq extra -> liboqs-python==0.16.0.1 (OQS C 0.16.0), generate_key PQ/hybrid delegation (thin slice). Current branch state: re-pins only; delegation preserved in docs/keyutils-py-delegation.patch.
Scope rule honored: NO mock_ca/ changes. Every deficiency below is a keyutils-py-side fix (K1-K6, K9) or an upstream-OQS fact the package should document (K7-K8).

## Test matrix

| Gate | Config | Baseline (re-pins, pre-delegation) | Post-delegation (measured 2026-10-21) |
|---|---|---|---|
| unit tests | A: without liboqs | 1136 passed / 39 failed / 11 errors (439s) | 979 passed / 221 failed / 41 errors — **157 new failures** |
| unit tests | B: liboqs-python 0.16.0.1, OQS C 0.16.0 (OQS_INSTALL_PATH=/opt/oqs-0.16) | 1191 passed / 0 failed / 4 errors (all mock-ca env: ocsp, register_routes) | 1024 passed / 188 failed / 34 errors — **167 new failures** |
| RF tests/ (CMP, non-verbose, env=cloudpki, live CA) | B | 255 tests: 3 passed / 185 failed / 67 skipped — 100% caused by live-CA outage (see K7b) | NOT RE-RUN — blocked by K7b, unrelated to the code change |
| RF tests_pq_and_hybrid/ (non-verbose, env=cloudpki, live CA) | B | 153 tests: 0 passed / 142 failed / 11 skipped — 100% caused by live-CA outage (see K7b) | NOT RE-RUN — blocked by K7b, unrelated to the code change |

Pass criterion applied: zero NEW failures versus the baseline in the same config (absolute green was never the criterion: config A legitimately fails the liboqs-gated PQ tests that have no local fallback; the 4 config-B errors are pre-existing mock-ca environment errors present before any change).

**Verdict: the delegation slice FAILS the criterion in both configs** (157 / 167 new failures, 0 fixed). Two mechanisms, both verified from the test logs:

1. **Class identity (K1)** — dominant in config B. Host code dispatches on `pq_logic.keys` wrapper classes (`ensure_is_sign_key`, `isinstance` checks across `resources/`, `pq_logic/`, `mock_ca/`). Delegated keys fail every such check. Dominant new error: `the provided key is not allowed to be used for signing: <class 'keyutils_py.keys.composite_sig.CompositeSigPrivateKey'>` (50x), plus `keyutils_py.keys.stateful_sig_keys.XMSSPrivateKey/HSSPrivateKey` and `keyutils_py.keys.sig_keys.MLDSAPrivateKey`. Blast radius: all `CAHandler`-based mock-ca tests (constructor builds a composite key and cert → ValueError), composite/sun-hybrid cert building, key loading/export, SPKI/sig-alg mapping, KGA signers.
2. **No-liboqs contract change (K4/K6)** — dominant in config A. The local factory has a pure-Python fallback for some PQ algorithms (FrodoKEM via `pq_logic/fips/frodokem.py` — `TestFrodoKEM` PASSED in the no-liboqs baseline; ML-DSA likewise), so no-liboqs was a first-class supported configuration. The delegated path has no fallback and raises `keyutils_py.exceptions.MissingOQSDependencyError` (72x in config A) instead. It is an `ImportError` subclass, so tests asserting `ImportError` keep passing; direct key-generation tests fail.

The delegation is preserved as `docs/keyutils-py-delegation.patch` (57 lines) and the ADR is
`docs/adr/0003-generate-key-delegation-to-keyutils-py.md` (status: proposed/on-hold). It is
re-applied once K1 and K2 are fixed in the package and the no-OQS contract (K4/K6) is decided.

## Environment / live-CA finding (blocks the RF gate, not the migration)

### K7b (external, verified 2026-10-21): the cloudpki live CA is broken server-side
Both RF suites fail 100% in SUITE SETUP before a single test executes: the initial registration
(IR, MAC-protected, RSA/ECC default keys) is rejected by the CA. Direct reproduction with the repo's own
helper functions (keyutils.generate_key -> build_ir_from_key -> protect_pkimessage -> POST to
https://broker.sdo-qa.siemens.cloud/.well-known/cmp) returns:

    HTTP 200
    status:      rejection
    statusString: PKIFreeText: upstream exchange: exception processing request at upstream interface for first bodyType 0
    failInfo:    00000000000000000000000001

A second IR with a fresh ECC key is rejected identically (reproducible, not transient over the observed
window). A malformed (garbage) POST is handled correctly by the front end (HTTP 400, clean JSON error
"unknown tag 27 encountered"), which proves the gateway/decoder layer is healthy and the exception is
raised in the CA's own upstream interface processing — i.e., server-side, independent of client code,
keys, or dependency pins. Consequence: the live RF gates cannot produce a meaningful baseline OR
post-migration run until the CA team fixes the upstream interface. The pre-migration RF numbers above
are therefore recorded as "live-CA outage" and must not be compared against a post-migration RF run
taken in the same outage window (they would be identically broken).
Action: re-run `make test env=cloudpki` and `make test-pq-hybrid env=cloudpki` (with
PATH="$PWD/.venv/bin:$PATH" and OQS_INSTALL_PATH set to a real OQS 0.16.0 prefix) once the CA is
healthy, on the branch tip (re-pin state, without the delegation) and again on the delegation.

## Issues for the keyutils-py package

### K1 (blocker for further migration slices): wrapper class identity — host isinstance checks fail on package keys
keyutils_py.keys.* is a near-copy of the host's pq_logic.keys.* (838 of 864 lines of
pq_logic/keys/sig_keys.py appear verbatim in keyutils_py/keys/sig_keys.py) but is a SEPARATE class
hierarchy:

    isinstance(keyutils_py.generate_key("ml-dsa-44"), pq_logic.keys.sig_keys.MLDSAPrivateKey) == False

The host performs isinstance dispatch on the local wrapper classes in many modules
(resources/keyutils.py:803,995,1126,1243,1300; resources/certutils.py:2077;
resources/protectionutils.py:2450,2651,2982; resources/cryptoutils.py:97,669;
resources/oid_mapping.py:222; resources/envdatautils.py:2214; resources/prepare_alg_ids.py:738;
pq_logic/combined_factory.py:141,740,795; and more). Any key object created through
keyutils_py.generate_key therefore breaks host dispatch (save/load, SPKI, protection, cert building).
The first migration slice is only safe on call paths that treat keys structurally; it is not complete
and cannot be widened until this is resolved.
Package-side resolution: keyutils-py must become the single source of truth for these classes and the
host's pq_logic must import them from the package (reverse the copy direction), or the package must
re-export under the host's import paths. The host cannot be patched to accept both hierarchies without
re-creating the duplication this extraction exists to remove.

### K2 (bug on ImproveQuality): FrodoKEM bitstring-5 port is incomplete (3 of 4 sites)
Commit 00d026a "adapt FrodoKEM to bitstring 5" fixed only keyutils_py/fips/frodokem.py:394
(pack: BitArray(N) -> BitArray.from_zeros(N)). On bitstring 5.0.0 the package copy still breaks at:
- line 294 `__bytes_to_bit_array`: `BitArray(length=8*len(B))` — length-only constructor
  (ValueError: "A length can't be given without an initialiser");
- line 360 `decode`: `BitArray(length=self.B*self.mbar*self.nbar)` — same;
- line 656 (decapsulation, S-matrix parse): `bitstring.ConstBitStream(sk[...])` —
  `ConstBitStream` was REMOVED in bitstring 5 (AttributeError: module 'bitstring' has no
  attribute 'ConstBitStream'); the bitstring-5 equivalent is
  `bitstring.Reader(...).read_value(...)`, or (as the host did) plain
  `struct.unpack_from('<H', ...)` since the data is whole 16-bit integers.
The host had to fix all four sites to run its own copy (`pq_logic/fips/frodokem.py`: three
`BitArray.from_zeros` conversions + the S-matrix parse rewritten as
`struct.unpack_from('<H', sk, ...)` — the same little-endian idiom the file already uses at
six other sites, verified value-identical against the old `ConstBitStream(...).read('intle:16')`
and the FrodoKEM unit tests). Note the breakage is in the pure-Python FrodoKEM
backend only; the OQS-backed path does not execute this code.

### K3 (API gap): XMSS/XMSSMT name conventions do not cover the host's names
The host passes e.g. "xmss-shake256-h10-256" (no underscore between name and hash, no underscore in
the h-N part); the package only accepts the OQS-native "xmss-shake_10_256" / "xmssmt-sha2_20/2_256"
style. keyutils_py.generate_key("xmss-shake256-h10-256") raises ValueError("Unsupported XMSS
algorithm"). Host unit tests (unit_tests/tests_pqc_and_hybrids/tests_pqc_stateful_sigs/...) and any RF
test using host-style names will fail when routed through the package.
Package-side resolution: normalize both spellings (accept the host's hyphen convention as an alias),
or document the canonical name set in the package README and expose a mapping helper.

### K4 (contract): generate_key no longer accepts traditional algorithms or seed=
keyutils_py.generate_key raises NotImplementedError for rsa/dsa/ec*/ed*/dh (moved to
generate_key_based_on_alg_id / TradKeyFactory) and dropped the deterministic seed= path. The host's
public keyword Generate Key (59 RF call sites + ~333 unit-test call sites) still carries the
trad + seed= contract, so the host keeps those paths local (thin delegation). Package-side note:
document the contract split (by-name PQ/hybrid vs by-OID trad vs seed-based) in the README so the
next migration slices have a stable target contract.

### K5 (dependency conflict): pins are unsatisfiable with the host's previous pins
bitstring==5.0.0 vs host 4.4.0, pycryptodome>=3.24.1 vs host 3.23.0 (verified via uv lock: conflicts).
The host re-pinned (worktree commit "Update bitstring to 5.0.0 and pycryptodome to 3.24.1"). Also note
the cryptography<51 upper bound, which will constrain future host upgrades.

### K6 (dependency): pq extra points at the same unpinned fork the host used
keyutils-py [pq] = liboqs-python @ git+https://github.com/Guiliano99/liboqs-python-stateful-sig.git
(unpinned HEAD, builds OQS C 0.15.0). A host running liboqs-python 0.16.0.1 (OQS C 0.16.0) would
disagree with a package that pulls C 0.15.0 into the same interpreter. Recommend pinning the package
pq extra to liboqs-python==0.16.0.1 (official, reproducible).

### K7 (upstream-OQS fact, document in package): OQS C 0.16.0 removed SPHINCS+ and renamed others
liboqs 0.16.0 release: "SPHINCS+ was removed." Also: old unsalted FrodoKEM -> eFrodoKEM-* (salted
takes the FrodoKEM-* names; ciphertext sizes change); SLH-DSA names moved to the underscore
convention (SLH_DSA_PURE_* / SLH_DSA_*_PREHASH_*). The host RF suite references SPHINCS+
(tests_pq_and_hybrid/pq_sig_tests.robot), so those RF tests cannot pass on any 0.16.0-based
configuration (MechanismNotSupportedError) — an upstream-OQS effect, not a migration effect. The
package should state its minimum OQS C version and list the removed/renamed mechanisms.

### K8 (reproducibility): the OQS C build location is env-dependent and silently stale
liboqs-python compiles (or finds) the C library on first import. Precedence: $OQS_INSTALL_PATH first,
then the default $HOME/_oqs, then an auto-build. A stale $HOME/_oqs (this container holds a 0.15.0
build there) is silently loaded instead of the version matching the wheel — verified: with
OQS_INSTALL_PATH unset the default path loaded C 0.15.0 while the wheel is 0.16.0.1; the wrapper only
emits a UserWarning, it does not refuse.
Package/wrapper-side suggestions: (a) fail (or at least loudly warn per-import) when the loaded C
version is older than the wheel's expected version; (b) document OQS_INSTALL_PATH / PYOQS_VERSION /
PYOQS_ENABLE_FAULTHANDLER in the README as the supported configuration surface. Gate-side workaround
(used in this trial): always set OQS_INSTALL_PATH explicitly and verify oqs.oqs_version().

### K9 (coverage, to verify): stateful-sig name acceptance
keyutils_py accepts "hss" (default hss_lms_sha256_m32_h5_lmots_sha256_n32_w8) and "levels=" for HSS
(verified generating). XMSS name aliasing is the open item (K3). LMS name conventions still need to
be checked against the host's unit-test inputs before sign-off of a stateful-sig migration slice.

## Reproduction commands used (for the keyutils-py maintainers)
    # env
    export OQS_INSTALL_PATH=/opt/oqs-0.16        # OQS C 0.16.0, all STFL flags ON
    # K1
    .venv/bin/python -c "import keyutils_py, sys; sys.path.insert(0,'resources'); \
      import pq_logic.keys.sig_keys as s; \
      print(isinstance(keyutils_py.generate_key('ml-dsa-44'), s.MLDSAPrivateKey))"
    # K2  (bitstring 5.0.0 installed; pure-Python FrodoKEM backend)
    .venv/bin/python -c "import sys; sys.path.insert(0,'resources'); \
      from resources.keyutils import generate_key; k = generate_key('frodokem-976-aes'); \
      ct, ss = k.public_key().encaps(); assert k.decaps(ct) == ss  # decaps hits line 656
      "
    # K3
    .venv/bin/python -c "import keyutils_py; keyutils_py.generate_key('xmss-shake256-h10-256')"
    # K4
    .venv/bin/python -c "import keyutils_py; keyutils_py.generate_key('rsa')"
    # K8  (unset OQS_INSTALL_PATH -> wrapper loads the stale $HOME/_oqs build)
    env -u OQS_INSTALL_PATH .venv/bin/python -c "import oqs; print(oqs.oqs_version())"

## Out of scope (host side, already handled or logged)
- Host re-pins + host-side `pq_logic/fips/frodokem.py` bitstring-5 fix (4 sites, including the
  `ConstBitStream` removal, see K2): done, committed.
- SPHINCS+ RF tests on OQS 0.16.0: host-side test adaptation needed; not part of this trial.
- Live-CA outage (K7b): external; gates to be re-run when the CA is healthy.
