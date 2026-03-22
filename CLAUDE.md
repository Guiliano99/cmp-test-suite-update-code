# CLAUDE.md — AI Assistant Guide for CMP Test Suite

This document provides essential context for AI assistants working on this codebase.

---

## Project Overview

This is the **CMP Test Suite** — a comprehensive compliance test suite for the
Certificate Management Protocol (CMP), developed by Siemens AG. It tests CMP
implementations against:

- **RFC 9810** — Certificate Management Protocol (CMP)
- **RFC 9483** — Lightweight Certificate Management Protocol (Lightweight CMP)
- **Post-quantum and hybrid cryptography** extensions (ML-KEM, ML-DSA, SLH-DSA, etc.)

The suite includes a built-in **Mock CA** (Flask-based) for isolated testing, and
integrates with real CA systems such as EJBCA and CloudPKI.

**Current version:** 0.0.2
**License:** Apache-2.0
**Copyright:** 2024–2025 Siemens AG

---

## Repository Layout

```
.
├── config/               # Environment-specific Robot Framework variable files
│   ├── cloudpki.robot    # CloudPKI environment config
│   ├── mock_ca.robot     # Mock CA environment config
│   ├── local.robot       # Local test environment config
│   ├── ejbca.robot       # EJBCA environment config
│   └── cert/             # Test certificates and keys for each environment
├── data/                 # Static test fixtures (never generated at runtime)
│   ├── csrs/             # Pre-generated Certificate Signing Requests
│   ├── keys/             # Pre-generated cryptographic key pairs (68 files)
│   ├── mock_ca/          # Mock CA-specific test data
│   ├── rfc_test_vectors/ # Official RFC test vectors
│   ├── trustanchors/     # Root CA trust anchor certificates
│   ├── unittest/         # Data used by Python unit tests
│   └── EJBCA/            # EJBCA-specific configuration data
├── doc/                  # Auto-generated HTML documentation (via `make docs`)
├── mock_ca/              # Mock CA server implementation (Flask, ~15 modules)
├── pq_logic/             # Post-quantum and hybrid cryptography logic
│   ├── keys/             # PQ key generation/handling (~21 modules)
│   ├── hybrid_sig/       # Hybrid signature schemes (~5 modules)
│   └── fips/             # FIPS-approved algorithm handling
├── resources/            # Core library code consumed by Robot Framework tests
│   ├── keywords.resource # Robot Framework keyword definitions (88KB)
│   ├── cmputils.py       # CMP message creation/parsing (237KB)
│   ├── certbuildutils.py # Certificate building (143KB)
│   ├── ca_ra_utils.py    # CA/RA logic (192KB)
│   ├── ca_kga_logic.py   # Key Generation Agent logic (106KB)
│   ├── checkutils.py     # Validation and response checking (111KB)
│   ├── certutils.py      # Certificate parsing and utilities (97KB)
│   ├── keyutils.py       # Key handling and format conversions (56KB)
│   ├── cryptoutils.py    # Cryptographic operations (44KB)
│   ├── typingutils.py    # Custom type aliases used project-wide
│   └── ...               # Additional utility modules
├── scripts/              # Utility scripts for test generation and setup
│   ├── docker_entrypoint.py
│   ├── setup_pq.sh       # Install liboqs / PQ dependencies
│   └── generate_*.py     # Test case generators
├── tests/                # Robot Framework integration tests (15 .robot files)
├── tests_mock_ca/        # Tests that run against the Mock CA
├── tests_pq_and_hybrid/  # Post-quantum and hybrid algorithm tests (11 .robot files)
├── unit_tests/           # Python unit tests (100+ modules, organized by category)
│   ├── tests_keys_related/
│   ├── tests_pqc_and_hybrids/
│   ├── tests_protocol_related/
│   ├── tests_ca_ra_utils/
│   ├── tests_cert_related/
│   ├── tests_build_messages/
│   └── ...
├── LICENSES/             # SPDX license files (Apache-2.0, CC0-1.0, etc.)
├── Makefile              # Primary build/task automation
├── Makefile_EJBCA        # EJBCA-specific Makefile targets
├── pyproject.toml        # Python package metadata, ruff/robotidy settings
├── requirements.txt      # Runtime Python dependencies
├── requirements-dev.txt  # Development/CI Python dependencies
├── .gitlab-ci.yml        # GitLab CI pipeline
├── .github/workflows/    # GitHub Actions (Docker builds, quality checks)
├── VERSION               # Current version string
└── *.md                  # Documentation: readme.md, CONTRIBUTING.md, etc.
```

---

## Key Documentation Files

| File | Purpose |
|------|---------|
| `readme.md` | Quick start, installation, and basic usage |
| `MockCA_readme.md` | Detailed Mock CA setup and API documentation |
| `about_suite.md` | Test suite architecture, tags, and test categories |
| `about_pq.md` | Post-quantum cryptography algorithms and usage |
| `CONTRIBUTING.md` | Contribution guidelines and code review process |
| `REFERENCES.md` | RFCs, standards, and external references |
| `SERVER_TEST_COVERAGE.md` | Matrix of tests vs. RFC sections covered |
| `TODOs.md` | Outstanding tasks and roadmap items |
| `cmp_issues_and_proposals.md` | Known protocol ambiguities and proposals |

---

## Development Workflows

### Running Tests

```bash
# Integration tests (default: cloudpki environment)
make test

# Integration tests including verbose variants
make test-verbose

# Post-quantum and hybrid tests
make test-pq-hybrid

# Tests against Mock CA
make test-mock-ca

# Python unit tests
make unittest

# Dry-run — load all tests without executing
make dryrun

# Timestamped test results
make testlog
```

To target a different environment, pass `env=<name>`:
```bash
make test env=mock_ca
make test env=ejbca
make test env=local
```

### Running the Mock CA

```bash
make start-mock-ca   # Starts Flask server on port 5000
```

### Code Quality

```bash
# Full quality check suite (ruff, pylint, pyright, reuse, codespell)
make verify

# Auto-format Python with ruff
make autoformat

# Generate HTML documentation
make docs
```

### Docker

```bash
# Unit tests inside Docker
make unittest-docker

# Build Docker images (base, dev, production)
# Triggered automatically by GitHub Actions on dependency/Dockerfile changes
```

---

## CI/CD Pipelines

### GitHub Actions (`.github/workflows/`)

| Workflow | Triggers | Jobs |
|----------|----------|------|
| `check_quality.yml` | Push/PR | ruff lint, license check, RF style, spelling, dependency check, version check, pylint, unit tests, pyright type check |
| `build_docker_images.yml` | Dependency/Dockerfile changes or manual | Build and push Docker images to GHCR |

### GitLab CI (`.gitlab-ci.yml`)

Stages: **unit tests → code style → static analysis**

| Job | Tool | Threshold |
|-----|------|-----------|
| `basics` | ruff | Must pass |
| `license-check` | reuse | Must pass |
| `robot-framework` | robocop | Must pass |
| `pylint` | pylint | fail-under=9.38 |
| `unit-tests` | pytest | Must pass |
| `pyright` | pyright | Max 85 errors allowed |

---

## Language & Technology Stack

| Layer | Technology |
|-------|-----------|
| Integration tests | Robot Framework 7.4.2 (`.robot` files) |
| Unit tests | Python unittest / pytest |
| Main library | Python 3.11+ |
| Cryptography | `cryptography` 46.x, `pycryptodome`, `pyasn1`, `tinyec` |
| PQ cryptography | liboqs (via `setup_pq.sh`), `pyhsslms` |
| Mock CA server | Flask 3.1.x |
| ASN.1 | pyasn1 0.6.x + pyasn1-alt-modules |
| PKI validation | pkilint 0.13.x |
| Linting | ruff, pylint, robocop |
| Formatting | ruff (Python), robotframework-tidy (Robot) |
| Type checking | pyright |
| License | reuse (SPDX compliance) |

---

## Code Conventions

### Python

- **Line length:** 120 characters (configured in `ruff.toml` and `.pylintrc`)
- **Formatter:** ruff (`make autoformat`)
- **Type checking:** pyright (incremental; current error budget ≤ 85)
- **Naming:**
  - Files and functions: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_CASE`
- **Imports:** Prefer top-level module imports (e.g., `import cryptoutils`) over
  deep attribute imports from within the module
- **Type hints:** Extensively used; custom aliases live in `resources/typingutils.py`
  (e.g., `Strint` for string-encoded integers)
- **Robot Framework integration:** Functions not intended as RF keywords are
  decorated with `@not_keyword`
- **Docstrings:** Standard docstrings in all public functions; ruff docstring rules
  apply except where `# noqa: D417` is used for RF keyword docs
- **SPDX headers:** Every source file must include an SPDX license identifier and
  copyright header — enforced by `reuse`

### Robot Framework

- **Tests:** Written as descriptive sentences (e.g., `Smoke test must pass`)
- **Tags:** Lowercase with hyphens (e.g., `verbose-tests`, `resource-intensive`,
  `setup`, `smoke`, `crypto`, `signature`, `mac`, `trust`)
- **Configuration:** Injected via environment variables; config files in `config/`
- **Keyword library:** `resources/keywords.resource` is the main entry point
- **Verbose vs. standard:** Tests tagged `verbose-tests` are excluded from `make test`
  and only run with `make test-verbose`

### Test Data

- **Static-first:** Prefer pre-generated fixtures in `data/` over runtime generation
- **Format:** Textual formats (PEM) preferred over binary for readability
- **Replicability:** Test data is committed to version control; keys and CSRs in `data/keys/` and `data/csrs/`

---

## Core Module Reference

| Module | Location | Purpose |
|--------|----------|---------|
| `cmputils` | `resources/cmputils.py` | CMP PKIMessage building/parsing; IR/CR/KUR/RR/KGA |
| `certbuildutils` | `resources/certbuildutils.py` | CSR and certificate template construction |
| `ca_ra_utils` | `resources/ca_ra_utils.py` | Certificate issuance and RA operations |
| `ca_kga_logic` | `resources/ca_kga_logic.py` | Key Generation Agent request/response handling |
| `checkutils` | `resources/checkutils.py` | Response validation, PKIStatus, chain checking |
| `certutils` | `resources/certutils.py` | Certificate parsing, subject/issuer, extensions |
| `keyutils` | `resources/keyutils.py` | Private/public key loading and format conversions |
| `cryptoutils` | `resources/cryptoutils.py` | Signatures, hashing, encryption |
| `asn1utils` | `resources/asn1utils.py` | ASN.1 encoding/decoding helpers |
| `protectionutils` | `resources/protectionutils.py` | MAC and signature-based CMP protection |
| `general_msg_utils` | `resources/general_msg_utils.py` | CMP general messages (support messages) |
| `oid_mapping` | `resources/oid_mapping.py` | OID definitions and algorithm mapping |
| `typingutils` | `resources/typingutils.py` | Custom type aliases (`Strint`, etc.) |
| `pq_logic/` | `pq_logic/` | PQ key factories, hybrid signatures, KEM operations |
| `mock_ca/ca_handler` | `mock_ca/ca_handler.py` | Mock CA Flask server entry point |

---

## Post-Quantum Cryptography

The `pq_logic/` package implements support for:

| Algorithm type | Algorithms |
|---------------|-----------|
| Signature (PQ) | ML-DSA (Dilithium), SLH-DSA (SPHINCS+) |
| Signature (Stateful) | XMSS, HSS/LMS |
| KEM | ML-KEM (Kyber), FrodoKEM |
| Hybrid signature | Composite signatures, chained signing |

Setup requires installing `liboqs`:
```bash
bash scripts/setup_pq.sh
```

PQ-specific tests live in `tests_pq_and_hybrid/`.

---

## Making Changes: Guidelines for AI Assistants

1. **Read before modifying** — Always read the relevant file(s) before suggesting
   changes. The large resource files (`cmputils.py`, `ca_ra_utils.py`, etc.) contain
   intricate protocol logic.

2. **Run quality checks after changes:**
   ```bash
   make verify       # Full suite
   make autoformat   # Auto-fix formatting issues
   make unittest     # Verify unit tests pass
   ```

3. **Follow SPDX conventions** — Every new file needs an SPDX header. Example:
   ```python
   # SPDX-FileCopyrightText: 2024 Siemens AG
   #
   # SPDX-License-Identifier: Apache-2.0
   ```

4. **Test data:** Do not generate test data at runtime in tests; add static fixtures
   to `data/` instead.

5. **Robot Framework keywords:** Expose Python functions to RF by omitting the
   `@not_keyword` decorator. Internal helpers should use `@not_keyword`.

6. **Type budget:** The pyright error count must stay at or below 85. Run
   `pyright` (or `make verify`) to check before pushing.

7. **Pylint score:** Maintain pylint score ≥ 9.38 (CI threshold). Run
   `pylint resources/ mock_ca/ pq_logic/` locally.

8. **Do not modify pre-generated test data** in `data/keys/`, `data/csrs/`,
   or `data/rfc_test_vectors/` without a clear reason — these are stable fixtures.

9. **Environment config:** Test environment differences belong in `config/*.robot`
   files, not in test or library code.

10. **Avoid breaking the Mock CA:** The Mock CA is a shared component used by
    integration tests. Changes to `mock_ca/` require running `make test-mock-ca`.

---

## Useful One-Liners

```bash
# Check which tests would run (dry run)
make dryrun

# Lint only
make verifyformat

# Start Mock CA in background
make start-mock-ca &

# Run a single Robot Framework test file
python -m robot --variable environment:mock_ca tests/basic.robot

# Run unit tests for a specific sub-package
python -m pytest unit_tests/tests_keys_related/

# Generate keyword documentation
make docs
```

---

## Version & Changelog

The version is stored in `VERSION`. Update it and add an entry to `CHANGELOG.md`
(if present) for any release. The CI `version_check` job validates consistency.
