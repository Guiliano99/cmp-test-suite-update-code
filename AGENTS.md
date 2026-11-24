<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md

This file provides guidance for coding agents (and human contributors) working in this repository.

## Project

`cmp-test-suite` is the **CMP Protocol Compliance Test Suite**. It verifies
Certificate Management Protocol (CMP) server implementations against
[RFC 9810](https://datatracker.ietf.org/doc/rfc9810/) and the CMP lightweight profile
[RFC 9483](https://datatracker.ietf.org/doc/html/rfc9483). Test cases are written in a
Robot Framework DSL; the suite generates CMP requests, exchanges them with a CMP
server, and validates responses. Results are written as `report.html`.

## Repository layout

- `tests/` – Robot Framework CMP test suites.
- `tests_mock_ca/`, `tests_pq_and_hybrid/` – additional suites (Mock CA, post-quantum).
- `resources/` – reusable Robot keywords and Python helpers (`resources/*.py`,
  `resources/*.resource`).
- `mock_ca/`, `pq_logic/` – Mock CA implementation and post-quantum logic.
- `config/` – environment resource files (e.g. `config/local.resource`).
- `unit_tests/` – pytest unit tests for the helper code.
- `data/`, `client_tests/` – test data, certificates, fixtures.
- `scripts/` – maintenance scripts.
- `doc/` – generated documentation (`make docs`).

## Setup

Install [`uv`](https://docs.astral.sh/uv/getting-started/installation/), then run one of the `uv sync` commands. It creates `.venv`.

```bash
uv sync               # core dependencies
uv sync --extra pq    # optional post-quantum support
uv sync --all-extras  # development dependencies
source .venv/bin/activate
```

## Common commands

- `make test` – run all tests for the default environment.
- `make test env=mock_ca` – run against the Mock CA.
- `make test-verbose` / `make testlog` – verbose or timestamped runs.
- `make unittest` – run unit tests (`pytest` with `PYTHONPATH=./resources`).
- `make docs` – generate keyword/function documentation.
- `scripts/generate_*_tests.py` / `scripts/generate_alg_test_cases.py` – generate Robot test
  cases and algorithm matrices; regenerate outputs when referenced RFC/CMP behavior changes.
- `make verify` / `make verifyformat` – sanity/formatting checks.
- `make start-mock-ca` – start the local Mock CA server.

## Coding standards

- Python: follow `ruff.toml` (line length 120) and `.pylintrc`. Run
  `make autoformat` (`ruff`) on changed files.
- Robot Framework: follow `robocop.toml`; run `robocop` where applicable.
- Type checking: `pyright` is configured via `pyrightconfig.json`
  (includes `./resources`, `./pq_logic`, `./mock_ca`).
- Keep diffs minimal and focused. Do not revert other contributors' changes.

## Licensing and REUSE

This project follows the REUSE convention. Every new file must carry an SPDX
license header (see existing files, e.g. `<!-- SPDX-FileCopyrightText: ... -->`
for Markdown). For files that cannot be annotated, add an entry to `REUSE.toml`.
The default license is `Apache-2.0` (Copyright Siemens AG, 2024).

## Agent notes

- Prefer existing keywords in `resources/` over reimplementing CMP logic.
- Do not regenerate or commit generated artifacts (`report.html`, `output.xml`,
  `log.html`, bytecode caches) unless explicitly required.
- When adding IETF-derived structures, follow the repository's ASN.1/pyasn1
  preparation helpers and their tests (see `.agents/skills` if available).
- When changing referenced algorithms, RFCs, or external citations, check and update
  `REFERENCES.md` (where present) so version and source references stay current.
  Relevant CMP algorithm profiles include RFC 9481 and RFC 9483.
- When adding new test cases, run the targeted Robot suites and `make unittest`
  before claiming completion.
