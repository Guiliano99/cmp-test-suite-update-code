---
name: python-function-documentation
description: "Implement or extend Python functions with correct module placement, typing, docstrings, and user-facing documentation updates in the cmp-test-suite. Use when production Python logic and its documentation both change. Do not use when the task is only unit-test authoring or final quality-gate execution. Applies to the cmp-test-suite only: pkixutils uses Sphinx docstrings."
---

# Add a Python Function and its Documentation

## Overview

Use this workflow to add a Python function that follows the conventions of the cmp-test-suite and is documented for
developers and for test authors. Commands run from the repository root with `.venv/bin/python`, the environment
that `uv sync` creates.

Related skills, if they are installed: `write-unit-tests` and `python-unit-test-given-when-then` when only tests
need an update; `python-quality-gate` as the last gate after the implementation.

Patterns to copy are in [examples.md](examples.md).

## 1) Choose the owning module first

Place the function where similar logic already lives. Search for neighbors:

```bash
grep -rn "def " resources pq_logic --include='*.py'
```

- `resources/*.py`: core CMP utility, building and parsing logic.
- `pq_logic/*.py`: PQ and hybrid logic.
- `unit_tests/*`: test helpers only.

Extend an existing module unless the responsibility is clearly new.

## 2) Define the contract before coding

Decide the name, the inputs and their types, the return type, the errors, and whether Robot Framework (RF) tests call
the function as a keyword.

## 3) Implement with the project style

- Type hints for the arguments and the return value.
- Reuse existing helpers instead of duplicating logic.
- Keep side effects explicit and small.
- Catch broad exceptions only where there is a recovery policy.
- RF exposes every public function of a library as a keyword. Mask a function that is no keyword with
  `@not_keyword` (`robot.api.deco`), see `CONTRIBUTING.md`, "Mask internal-use Python functions".

## 4) Write the docstring at implementation time

CONTRIBUTING.md ("Documenting Python keywords") says that keyword docstrings follow the RF conventions, and that
`ruff` is silenced for them with `# noqa: D417 for RF docs`, because the docstrings are written for the RF
documentation. Look for that comment in `resources/` to find examples.

| Function | Docstring |
|---|---|
| private (`_name`) or `@not_keyword` | one line, or Sphinx (`:param:`, `:return:`, `:raises:`) without `:rtype:`, or an RF docstring |
| any other function, and every `@keyword` | RF docstring with the sections that apply |

An RF docstring has these sections in this order. Each has a dashed underline, and its lines start with `-`
(`Examples:` has table lines that start with `|`):

| Section | When |
|---|---|
| `Arguments:` | the function has parameters |
| `Returns:` | the function returns a value |
| `Raises:` | the function contains a `raise`; a function may also name errors of the functions it calls |
| `Examples:` | always: RF table lines with the keyword name as RF shows it |

What the practice of the repository shows, measured on the functions marked `# noqa: D417 for RF docs` in
`resources/` (6 functions): all 6 have `Arguments:` and `Examples:`, 5 have `Returns:` and 4 have `Raises:`. The one
without `Returns:` returns nothing (`try_to_log_pkimessage`), and the two without `Raises:` raise nothing
themselves. Counting `pq_logic/` too, there is one more, with all four sections. Of the 354 module-level functions in
`resources/` that are neither private nor `@not_keyword`, 320 have an RF docstring, 25 a Sphinx one, 8 another form
and 1 none. In the RF ones `Arguments:` is always there, `Examples:` in 312, `Returns:` in 234 and `Raises:` in 247 (60 of them without a `raise` in the function itself).
So a section that does not apply is left out, and the checker requires only the ones that apply.

## 5) Wire call sites and exports

Update the call sites and the imports, and keep the names consistent with the neighbors.

## 6) Add tests

Add or extend unit tests near the owning module: the normal path, the invalid input path, and an edge case.

```bash
PYTHONPATH=./resources .venv/bin/python -m pytest unit_tests -k "<function_name_or_feature>"
```

## 7) Update the documentation

When the function changes what contributors or test authors see, update `readme.md`, `MockCA_readme.md` or the
documents in `doc/`. Say what changed, how to call it and what limits it has. `make docs` regenerates the RF
documentation in `doc/`.

## 8) Final validation

```bash
PYTHONPATH=./resources .venv/bin/python -m pytest unit_tests -k "<function_name_or_feature>"
make unittest
.venv/bin/python .agents/skills/python-function-documentation/scripts/check_docstring_style.py <file_or_dir>... [--since <git ref>]
```

The checker (`scripts/check_docstring_style.py`) checks the module-level functions against the table in step 4:

- Without `--since` it checks every function of the paths. On the commit e409ea82 it gives 75 findings in 18 of the 33
  files of `resources/`, and 22 in `pq_logic/`.
- `--since <git ref>` checks only the functions whose lines changed since the ref (`git diff -U0`, which includes
  uncommitted changes), and the files that git does not track yet. A function counts as changed from its first
  decorator to its last line. Use it on a branch: `--since origin/main`, or the commit before your work.
- Exit codes: 0 no violation, 1 a violation or no Python file, 2 git could not tell the changes (for example an
  unknown ref); the message is on stderr.

`ruff check` and `make verify` run the repository's own docstring rules as well.

## Implementation checklist

1. Select the owning module.
2. Define the function contract.
3. Implement with typing; mask it with `@not_keyword` if it is no keyword.
4. Write the docstring.
5. Wire call sites and imports.
6. Add or extend tests.
7. Update the documentation.
8. Run the targeted tests and `make unittest`.
9. Run the docstring checker for the changed files, with `--since`.

## Files in this skill

- `SKILL.md` - workflow and rules.
- `examples.md` - docstrings to copy.
- `scripts/check_docstring_style.py` - the docstring checker.
- `agents/openai.yaml` - discovery metadata.
- `.tags` - index tags.

## Completion checklist

- [ ] The function is in the right module and has a clear contract.
- [ ] Typing, docstring and call sites are consistent; a function that is no keyword has `@not_keyword`.
- [ ] The docstring has the sections that apply.
- [ ] The documentation is updated where the behavior is visible to users.
- [ ] The targeted tests, `make unittest` and the docstring checker (with `--since`) were run.
