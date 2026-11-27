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

## Make targets

Use the `make` target for a task when one exists. The targets set `--pythonpath`, `PYTHONPATH`,
the environment and the output folder, which hand-written `robot` or `pytest` calls often miss.
`make` takes `python`, `robot` and `ruff` from `PATH`: activate `.venv` first, or run
`uv run make <target>`.

The targets marked "yes" are allowed in `.claude/settings.json` (Claude Code) and
`.vscode/settings.json` (GitHub Copilot), so agents can run them without asking. They only read
the checkout, write ignored output files, or talk to the Mock CA on `127.0.0.1`. Ask the user
before running any other target.

| Task | Command | Allowed |
| --- | --- | --- |
| List the targets | `make help` | yes |
| Changed Python code in `resources/`, `pq_logic/` or `mock_ca/` | `make unittest` | yes |
| Changed a `.robot` or `.resource` file: check that all suites load (several minutes) | `make dryrun` | yes |
| Before a commit: reuse, ruff, pylint, pyright, codespell (needs the `dev` extra) | `make verify` | yes |
| Ruff only (seconds) | `make verifyformat` | yes |
| Start the Mock CA on `127.0.0.1:5000`; it runs until stopped | `make start-mock-ca` | yes |
| CMP suite (`tests/`) against the running Mock CA | `make test env=mock_ca` | yes |
| PQ and hybrid suite against the running Mock CA | `make test-pq-hybrid env=mock_ca` | yes |
| All three suites against the running Mock CA | `make test-mock-ca` | yes |
| Fix ruff findings; rewrites files in the whole repository | `make autoformat` | no |
| Regenerate the HTML documentation in `doc/` | `make docs` | no |
| Unit tests in Docker | `make unittest-docker` | no |
| Run against a real CA from `config/<name>.resource` | `make test env=<name>`, `make testlog env=<name>` | no |
| Verbose suites (long) | `make test-verbose`, `make test-mock-ca-verbose` | no |

- Without `env=`, the test targets use `env ?= cloudpki`, an external CA. Never run them
  without the user's go-ahead.
- The Robot suites use post-quantum keys: install the `pq` extra (`uv sync --extra pq`) before
  a test target. The unit tests do not need it.
- Start the Mock CA in the background before a Mock CA test target and stop it afterwards. It
  runs with the Flask debugger and reloader, so editing a `.py` file restarts it during a run.
- Some unit tests start their own Mock CA on port 6002; they fail if that port is in use.
- Robot writes its results to `reports/` (`make dryrun` to the repository root).
  `reports/readme.md` is tracked: do not delete the folder.
- `make` exits with 2 when a Robot test failed; the console output shows the counts.
- For one suite file, call Robot directly:
  `uv run robot --pythonpath=./ --variable environment:mock_ca --outputdir=reports tests/<file>.robot`
  (add `--dryrun` to only load it).
- `scripts/generate_*_tests.py` / `scripts/generate_alg_test_cases.py` – generate Robot test
  cases and algorithm matrices; regenerate outputs when referenced RFC/CMP behavior changes.

## Coding standards

- Python: follow `ruff.toml` (line length 120) and `.pylintrc`. Run
  `ruff check --fix <changed files>`; `make autoformat` fixes the whole repository.
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
