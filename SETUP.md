# SPDX-FileCopyrightText: Copyright 2025 Siemens AG

# SPDX-License-Identifier: Apache-2.0

# Setup Guide for the CMP Protocol Compliance Test Suite

This guide summarizes the requirements and environment questions needed to run the CMP
Protocol Compliance Test Suite against a user-provided CMP server implementation.

## 1. Software requirements

- Python 3.10+ recommended, installed and available as `python3`
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/), which creates the virtual environment `.venv`
- Robot Framework runtime dependencies from `pyproject.toml` / `uv.lock`
- Optional extras:
  - `uv sync --extra pq` for post-quantum support
  - `uv sync --all-extras` for development tools

## 2. Basic installation

```sh
uv sync
# or:
# uv sync --extra pq
# uv sync --all-extras
source .venv/bin/activate
```

## 3. Environment configuration

The suite uses an environment resource file, usually selected through `ENVIRONMENT`:

```sh
make test env=mock_ca
```

For a real CMP implementation, the LLM should guide the user to configure `config/${ENVIRONMENT}.resource`
or provide an equivalent environment resource containing at least:

- `${CA_BASE_URL}` or equivalentCMP CA URL
- `${CA_CMP_URL}`
- `${SENDER}` / `${RECIPIENT}`
- `${PRESHARED_SECRET}` or certificate/key credentials for MAC-based protection
- `${ISSUED_CERT}` and `${ISSUED_KEY}` for signature-protected tests
- other profile-dependent variables such as:
  - `${LWCMP}`
  - `${ALLOW_IMPLICIT_CONFIRM}`
  - `${ALLOW_ISSUING_OF_CA_CERTS}`
  - algorithm flags used by the selected server

## 4. Mock CA startup

For local testing without an external implementation:

```sh
make start-mock-ca
```

The suite can then be run against the local Mock CA, for example:

```sh
make test env=mock_ca
```

### Docker

Without a local Python setup, run the suite or the Mock CA in a container. Use the published
image, `ghcr.io/siemens/cmp-test`, or build it from this checkout:

```sh
docker build -t cmptest-base -f data/dockerfiles/Dockerfile.base .
docker build -t cmptest-tests -f data/dockerfiles/Dockerfile.tests .
```

The first build compiles liboqs, so it takes several minutes. Build from a checkout without a
`.venv` folder: `.dockerignore` only excludes `venv*`, so `.venv` would be copied into the image.

```sh
# smoke test, needs no CA
docker run --rm cmptest-tests --smoke

# Mock CA on http://127.0.0.1:5000/issuing
docker run --rm -it -p 127.0.0.1:5000:5000 cmptest-tests --mockca 5000

# in a second terminal; `make` needs the Python setup from section 2
curl -f http://127.0.0.1:5000/crl -o /tmp/mockca.crl
make test-mock-ca
```

- `-p` is required to reach the Mock CA from the host. Keep the `127.0.0.1:` prefix: the Mock CA
  runs with the Flask debugger enabled and must not be reachable from other machines.
- `docker run --rm cmptest-tests --help` lists all options (`--minimal URL`, `--customconfig`, ...).
- `make unittest-docker` runs the unit tests in the base image.

## 5. Running the suite

Examples:

```sh
make test
make test env=mock_ca
make test-verbose
make unittest
```

## 6. Questions the LLM should ask the human user before testing their implementation

The LLM should ask the user for the following details before generating commands or editing
environment files:

### Target server
1. What is the base URL of the CMP CA / PKI management entity?
2. Which CMP endpoints are exposed (exchange, polling, general messages)?
3. Does the server support HTTP transfer only, or also CoAP/offline transfer?

### Protection mode
4. Does the implementation support MAC-based protection (PBMAC1 / password-based MAC)?
5. Does it support signature-based protection? If yes, which signature algorithms?
6. What shared secret / pre-shared password should be used for MAC tests?
7. Which issued EE certificate and private key should be used for signature-protected requests?

### Certificate profile and issuance policy
8. Does the CA allow issuing CA certificates?
9. Is implicit confirmation enabled or required?
10. Which subject names and SAN values should be used for testing?
11. Which key algorithms and key usages should be tested?
12. Does the CA support central key generation (KGA), revocation, support messages, and cross-certification?

### LwCMP conformance scope
13. Is the target intended to conform to RFC 9483 LwCMP? (Set `${LWCMP}` accordingly.)
14. Is implicit confirmation required by policy (`${ALLOW_IMPLICIT_CONFIRM}`)?
15. Are granted-with-mods responses expected?

### Environment and reporting
16. Should the suite run against the repository's Mock CA first to establish a baseline?
17. Which test tags should be included (`minimal`, `positive`, `negative`, `mac`, `signature`, `lwcmp`, `config-dependent`)?
18. Should the run be verbose and should logs be timestamped (`make test-verbose` / `make testlog`)?

## 7. Recommended first-run workflow

1. Run `make unittest`.
2. Start and test the local Mock CA with `make start-mock-ca` and `make test env=mock_ca`.
3. Create or select an environment resource file for the user's implementation.
4. Answer the configuration questions above.
5. Run a tagged subset first, for example only `minimal` tests.
6. Increase coverage after the baseline passes.

## 8. Notes

- Do not commit generated artifacts (`report.html`, `output.xml`, `log.html`) unless explicitly required.
- When changing RFC or reference-dependent behavior, also check/update `REFERENCES.md` where present.
- Use the generator scripts when expanding test matrices rather than hand-writing large repetitive suites.


## 9. Client CMP implementation tests

The `client_tests/` folder contains an experimental client-side test suite.
It can be run independently from the server tests:

```sh
cd client_tests
uv run robot cmp_tests_jinja.robot
```

Requirements and notes (the `PKIHeader` keywords, `robot.toml` and `pathfix.py` are not on this branch yet):
- Start the Mock CA first (`python3 mock_ca/ca_handler.py` or `make start-mock-ca`).
- The suite can parse saved CMP PKIMessage files (`-reqout` / `-repout`) and identify their
  `PKIHeader` using `Identify PKIHeader` / `Identify PKIMessage Header`.
- `client_tests/robot.toml` sets `python-path = [".."]` so RobotCode and Robot Framework
  can resolve repository resources from `client_tests/`.
- `client_tests/pathfix.py` is imported first to make `resources/` and `pq_logic/`
  importable when running `robot` directly from that folder.

## 10. Robot Framework and MCP tooling

The `llm` dependency group in `pyproject.toml` provides them (`uv sync --extra llm`):

```txt
robotcode[runner,analyze]
robotframework-robocop[mcp]
```

Typical checks:

```sh
uv run robocop check client_tests/cmp_tests_jinja.robot
uv run robotcode analyze code client_tests/cmp_tests_jinja.robot
uv run robot --dryrun client_tests/cmp_tests_jinja.robot
```

Optional agent/MCP services used for Robot Framework:
- `rf-mcp` (`robotmcp`) for Robot Framework test/keyword discovery and execution. See
  [Install the RF MCP server](#install-the-rf-mcp-server).
- `robocop-mcp` is available after installing `robotframework-robocop[mcp]` and can be
  registered as an MCP server using the installed `robocop-mcp` executable.

### Install the RF MCP server

Install it as a uv tool, then register it for the agents you use:

```sh
uv tool install "rf-mcp==0.36.*"
robotmcp install --agents claude-code,codex,opencode --scope user --yes
```

- Do not register it through `uvx`. That stores a path inside the uv cache, and the server stops
  starting (`ENOENT`) when the cache is cleaned. To repair such an entry, run both commands above
  and add `--force` to the second.
- Keep the version pin. rf-mcp 2.0 (the `main` branch on GitHub) replaced `robotmcp install` with
  `rf-mcp init`.
- The tool has its own environment and cannot import this suite's Python libraries. To run the
  suite's keywords through MCP, start the server in the suite's environment instead, for example
  for Claude Code, from the repository root:

  ```sh
  claude mcp add robotmcp -- uv run --project "$PWD" --with "rf-mcp==0.36.*" robotmcp
  ```

- Restart the agent after registering. `claude mcp list` or `codex mcp list` shows the server.
