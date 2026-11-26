# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0
"""Check the docstring style of module-level functions.

- A private function (`_name`) or a function with `@not_keyword` has a one-line docstring, or a Sphinx docstring
  without `:rtype:`, or a Robot Framework docstring (one with an `Arguments:` section).
- Any other function is a Robot Framework keyword and has a docstring in the style of the keyword documentation
  (CONTRIBUTING.md, "Documenting Python keywords"). A Robot Framework docstring has the sections that apply to the
  function, in this order:

  - `Arguments:` if the function has parameters,
  - `Returns:` if it returns a value,
  - `Raises:` if it contains a `raise`,
  - `Examples:` always.

  A section that does not apply may be there. Each section has a dashed underline, and its lines start with `-`
  (`Examples:` has Robot Framework table lines that start with `|`).

`--since <git ref>` checks only the functions whose lines changed since that ref (`git diff -U0`), and the files that
git does not track yet.

Exit codes: 0 no violation, 1 a violation, 2 the changes could not be read from git.
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

ROBOT_SECTIONS: tuple[str, ...] = ("Arguments:", "Returns:", "Raises:", "Examples:")
SPHINX_FIELD_PATTERN = re.compile(r"^\s*:(param|type|return|returns|raise|raises)\b")
SPHINX_RTYPE_PATTERN = re.compile(r"^\s*:rtype:\s*")
HUNK_PATTERN = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@")

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


class GitError(Exception):
    """Git could not tell which lines changed."""


def _decorator_name(decorator: ast.expr) -> str | None:
    """Return the leaf name for decorator expressions such as `@x`, `@a.x`, or `@x(...)`."""
    if isinstance(decorator, ast.Call):
        return _decorator_name(decorator.func)
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        return decorator.attr
    return None


def _has_decorator(node: FunctionNode, decorator_name: str) -> bool:
    """Return whether `node` has decorator `decorator_name`."""
    return any(_decorator_name(decorator) == decorator_name for decorator in node.decorator_list)


def _is_private_function(function_name: str) -> bool:
    """Return whether a function name is private by convention."""
    return function_name.startswith("_") and not function_name.startswith("__")


def _non_empty_lines(docstring: str) -> list[str]:
    """Return stripped, non-empty lines from a docstring."""
    return [line.strip() for line in docstring.splitlines() if line.strip()]


def _is_sphinx_style(docstring: str) -> bool:
    """Return whether docstring uses Sphinx field directives."""
    return any(SPHINX_FIELD_PATTERN.match(line) for line in docstring.splitlines())


def _validate_sphinx_style(docstring: str) -> list[str]:
    """Validate additional Sphinx-style constraints."""
    if any(SPHINX_RTYPE_PATTERN.match(line) for line in docstring.splitlines()):
        return ["Sphinx-style docstrings must not include ':rtype:'."]
    return []


def _next_non_empty_line(lines: list[str], start_index: int) -> tuple[int, str] | None:
    """Return the next non-empty line at or after `start_index`."""
    for index in range(start_index, len(lines)):
        if lines[index]:
            return index, lines[index]
    return None


def _own_nodes(function_node: FunctionNode) -> Iterable[ast.AST]:
    """Yield the nodes of the function body without those of nested functions, lambdas and classes."""
    pending: list[ast.AST] = list(function_node.body)
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            pending.extend(ast.iter_child_nodes(node))


def _required_sections(function_node: FunctionNode) -> tuple[str, ...]:
    """Return the sections that apply: Arguments for parameters, Returns for a value, Raises for `raise`, Examples."""
    arguments = function_node.args
    has_parameters = bool(
        arguments.posonlyargs or arguments.args or arguments.kwonlyargs or arguments.vararg or arguments.kwarg
    )
    nodes = list(_own_nodes(function_node))
    returns_value = any(
        isinstance(node, ast.Return)
        and node.value is not None
        and not (isinstance(node.value, ast.Constant) and node.value.value is None)
        for node in nodes
    )
    raises = any(isinstance(node, ast.Raise) for node in nodes)
    applies = {"Arguments:": has_parameters, "Returns:": returns_value, "Raises:": raises, "Examples:": True}
    return tuple(section for section in ROBOT_SECTIONS if applies[section])


def _validate_robot_style(docstring: str, required: Sequence[str]) -> list[str]:
    """Validate a Robot Framework docstring that has to contain the `required` sections."""
    lines = [line.strip() for line in docstring.splitlines()]
    positions: dict[str, int] = {}
    for index, line in enumerate(lines):
        if line in ROBOT_SECTIONS and line not in positions:
            positions[line] = index

    missing = [section for section in required if section not in positions]
    if missing:
        return [f"Robot Framework docstring is missing sections: {', '.join(missing)}."]

    present = [section for section in ROBOT_SECTIONS if section in positions]
    errors: list[str] = []
    order = [positions[section] for section in present]
    if order != sorted(order):
        errors.append("Robot Framework section order must be: Arguments, Returns, Raises, Examples.")

    boundaries = [positions[section] for section in present] + [len(lines)]
    for section, start in zip(present, boundaries):
        underline_info = _next_non_empty_line(lines, start + 1)
        if underline_info is None or not re.fullmatch(r"-{3,}", underline_info[1]):
            errors.append(f"Section '{section}' must contain a dashed underline line.")
            continue

        end = min(boundary for boundary in boundaries if boundary > start)
        content_lines = [line for line in lines[underline_info[0] + 1 : end] if line]
        if not content_lines:
            errors.append(f"Section '{section}' must contain at least one content line.")
        elif section == "Examples:":
            if not any(line.startswith("|") for line in content_lines):
                errors.append("Section 'Examples:' must include at least one Robot Framework table line.")
        elif not any(line.startswith("-") for line in content_lines):
            errors.append(f"Section '{section}' must use bullet lines starting with '-'.")

    return errors


def check_function_docstring_style(function_node: FunctionNode) -> list[str]:
    """Check one function node and return its style violations."""
    docstring = ast.get_docstring(function_node, clean=True)
    location = f"line {function_node.lineno}, function `{function_node.name}`"

    if not docstring:
        return [f"{location}: missing docstring."]

    is_private = _is_private_function(function_node.name)
    has_keyword = _has_decorator(function_node, "keyword")
    has_not_keyword = _has_decorator(function_node, "not_keyword")

    if (has_not_keyword or (is_private and not has_keyword)) and "Arguments:" not in _non_empty_lines(docstring):
        if len(_non_empty_lines(docstring)) == 1:
            return []
        if _is_sphinx_style(docstring):
            return [f"{location}: {error}" for error in _validate_sphinx_style(docstring)]
        return [
            f"{location}: expected a one-line, a Sphinx-style (without ':rtype:') or a Robot Framework docstring "
            "for private/@not_keyword function."
        ]

    errors = _validate_robot_style(docstring, _required_sections(function_node))
    return [f"{location}: {error}" for error in errors]


def _line_range(node: FunctionNode) -> range:
    """Return the lines of a function, from its first decorator to its last line."""
    first = min([node.lineno, *(decorator.lineno for decorator in node.decorator_list)])
    return range(first, (node.end_lineno or node.lineno) + 1)


def check_python_source(source: str, filename: str = "<string>", changed: set[int] | None = None) -> list[str]:
    """Return the violations of the module-level functions in a source string.

    :param changed: only functions with a line in this set are checked; None checks all of them.
    """
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [f"{filename}:{exc.lineno or 0}:{exc.offset or 0}: unable to parse Python source: {exc.msg}"]

    errors: list[str] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if changed is not None and changed.isdisjoint(_line_range(node)):
            continue
        errors.extend(check_function_docstring_style(node))
    return [f"{filename}: {error}" for error in errors]


def check_python_file(file_path: Path, changed: set[int] | None = None) -> list[str]:
    """Return the violations of the module-level functions in a Python file."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{file_path}: unable to read file: {exc}"]
    return check_python_source(source=source, filename=str(file_path), changed=changed)


def _collect_python_files(paths: Iterable[Path]) -> list[Path]:
    """Return the Python files in the given files and directories."""
    files: set[Path] = set()
    for path in paths:
        if path.is_file() and path.suffix == ".py":
            files.add(path)
        elif path.is_dir():
            files.update(candidate for candidate in path.rglob("*.py") if candidate.is_file())
    return sorted(files)


def _git(*args: str) -> str:
    """Run git in the current directory and return its output; raise `GitError` if it fails."""
    try:
        result = subprocess.run(["git", *args], capture_output=True, text=True, check=False)  # noqa: S607
    except OSError as exc:
        raise GitError(f"cannot run git: {exc}") from exc
    if result.returncode != 0:
        raise GitError(f"git {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def parse_changed_lines(diff: str) -> dict[Path, set[int]]:
    """Return the changed line numbers per file from the output of `git diff -U0 --relative`.

    A hunk that only deletes lines marks the line before and the line after the deletion.
    """
    changed: dict[Path, set[int]] = {}
    current: set[int] | None = None
    in_header = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current, in_header = None, True
        elif in_header and line.startswith("+++ "):
            name = line[4:].removeprefix("b/")
            current = None if name == "/dev/null" else changed.setdefault(Path(name).resolve(), set())
        elif match := HUNK_PATTERN.match(line):
            in_header = False
            if current is not None:
                start, count = int(match.group(1)), int(match.group(2) if match.group(2) is not None else 1)
                current.update(range(start, start + count) if count else (start, start + 1))
    return changed


def changed_lines_since(ref: str, files: Iterable[Path]) -> dict[Path, set[int]]:
    """Return the changed line numbers of the files since `ref`; a file git does not track has all its lines."""
    paths = [str(path) for path in files]
    diff_options = ["-U0", "--relative", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/"]
    changed = parse_changed_lines(_git("diff", *diff_options, ref, "--", *paths))
    for name in _git("ls-files", "--others", "--exclude-standard", "--", *paths).splitlines():
        path = Path(name).resolve()
        changed[path] = set(range(1, len(path.read_text(encoding="utf-8").splitlines()) + 2))
    return changed


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Check the docstring style of module-level functions. Private and @not_keyword functions need a "
        "one-line or Sphinx docstring without :rtype:. Other functions need the Robot Framework sections that apply."
    )
    parser.add_argument("paths", nargs="+", help="Python files or directories to check.")
    parser.add_argument(
        "--since",
        metavar="REF",
        help="check only the functions whose lines changed since this git ref, and files that git does not track",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the checker; return 0 for no violation, 1 for a violation, 2 if git failed."""
    args = _parse_args(argv)
    files = _collect_python_files(Path(path) for path in args.paths)
    if not files:
        sys.stdout.write(f"No Python files found in: {', '.join(args.paths)}\n")
        return 1

    changed: dict[Path, set[int]] | None = None
    if args.since is not None:
        try:
            changed = changed_lines_since(args.since, files)
        except GitError as exc:
            sys.stderr.write(f"{exc}\n")
            return 2

    errors: list[str] = []
    for file_path in files:
        if changed is None:
            errors.extend(check_python_file(file_path))
        elif file_path.resolve() in changed:
            errors.extend(check_python_file(file_path, changed[file_path.resolve()]))
    if errors:
        sys.stdout.write("\n".join(errors) + "\n")
        return 1

    sys.stdout.write("No docstring style violations found.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
