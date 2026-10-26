---
name: python-function-documentation
description: "Implement or extend Python functions with correct module placement, typing, docstrings, and user-facing documentation updates in this CMP test-suite codebase. Use when production Python logic and its documentation both change. Do not use when the task is only unit-test authoring or final quality-gate execution."
---

# Add a Python Function + Documentation Workflow

## Overview

Use this workflow to add a Python function that matches repository conventions
and is documented for both developers and test users.

## Boundary and handoff

- Use this skill for production code implementation plus documentation behavior.
- Use [write-unit-tests](../write-unit-tests/SKILL.md) or [python-unit-test-given-when-then](../python-unit-test-given-when-then/SKILL.md) when only tests need updates.
- Use [python-quality-gate](../python-quality-gate/SKILL.md) as the final Python completion gate after implementation.

Concrete copy/adapt patterns are in [examples.md](examples.md).

## 1) Choose the owning module first

Place the function where similar logic already lives.

- Search for neighboring patterns:

```bash
rg -n "def .*\(" resources pq_logic unit_tests -g '*.py'
```

- Typical ownership:
    - `resources/*.py`: core CMP utility/building/parsing logic.
    - `pq_logic/*.py`: PQ/hybrid-specific implementation.
    - `unit_tests/*`: test helpers only.

Prefer extending an existing module over creating a new one unless the responsibility is clearly new.

## 2) Define function contract before coding

Decide and document:

- function name and intent,
- inputs and accepted types,
- return type,
- errors/validation behavior,
- whether it is internal helper or externally consumed API.

## 3) Implement with project style

- Add type hints for arguments and return value.
- Reuse existing helpers instead of duplicating logic.
- Keep side effects explicit and minimal.
- Avoid broad exception handling unless there is a clear recovery policy.

## 4) Write docstring at implementation time

Use a concise docstring that includes:

- one-line purpose,
- argument descriptions,
- return description,
- raised exceptions or failure conditions.

If the function is user-facing (used by Robot keywords or public utilities), make the docstring usage-oriented.

Docstring examples:

- Internal helper and user-facing patterns: [examples.md](examples.md)

## 5) Wire call sites and exports

- Update call sites to use the new function.
- Update module exports/imports where needed.
- Keep naming consistent with neighboring functions.

## 6) Add tests

Add or extend unit tests near the owning module.

Minimum coverage:

- normal/positive path,
- invalid input path,
- edge case relevant to function behavior.

Useful commands:

```bash
python -m pytest unit_tests -k "<function_name_or_feature>"
```

## 7) Update user/developer documentation

When the function changes behavior visible to contributors or test writers, update docs such as:

- `readme.md`,
- `MockCA_readme.md`,
- relevant docs in `doc/` or module-level docs.

Document what changed, how to call it, and any constraints.

## 8) Final validation

Run targeted tests first, then full unit tests:

```bash
python -m pytest unit_tests -k "<function_name_or_feature>"
make unittest
```

Run docstring style checks for changed Python files:

```bash
python3 .github/skills/python-skills/python-function-documentation/scripts/check_docstring_style.py <path/to/file_or_dir>
```

Run checker unit tests:

```bash
python3 -m unittest discover -s .github/skills/python-skills/python-function-documentation/unit_tests -p 'test_*.py'
```

Validation rules:

- private (`_name`) and `@not_keyword` functions: one-line docstring or Sphinx style without `:rtype:`
- all other module-level functions (public and/or `@keyword`): RobotFramework style with `Arguments`, `Returns`, `Raises`, and `Examples` sections

## Implementation checklist

1. Select owning module.
2. Define function contract.
3. Implement function with typing.
4. Add/update docstring.
5. Wire call sites/imports.
6. Add/extend tests.
7. Update relevant documentation.
8. Run targeted pytest.
9. Run `make unittest`.
10. Run docstyle checker for changed files.
11. Commit with a clear message.

## Files in this skill

- `SKILL.md` - Workflow for adding or extending Python functions with matching documentation updates.
- `examples.md` - Copy/adapt patterns for implementation and docstring structure.
- `scripts/check_docstring_style.py` - Docstring style checker used by the workflow.
- `unit_tests/test_check_docstring_style.py` - Tests for the docstring style checker.
- `agents/openai.yaml` - Agent-facing display metadata for the skill.
- `.tags` - Discovery keywords for Python implementation and documentation tasks.

## Completion checklist

- [ ] The function was added to the correct owning module with a clear contract.
- [ ] Typing, docstrings, and call sites were updated consistently.
- [ ] User-facing or contributor-facing documentation was updated where behavior changed.
- [ ] Targeted tests and docstring style checks were run for the affected files.
- [ ] The final change aligns implementation behavior with documentation.
