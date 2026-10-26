#!/usr/bin/env python3
"""Validate function docstring styles for the Python function documentation skill."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
import re
from typing import Iterable, Sequence

ROBOT_REQUIRED_SECTIONS: tuple[str, ...] = (
    "Arguments:",
    "Returns:",
    "Raises:",
    "Examples:",
)
SPHINX_FIELD_PATTERN = re.compile(r"^\s*:(param|type|return|returns|raise|raises)\b")
SPHINX_RTYPE_PATTERN = re.compile(r"^\s*:rtype:\s*")


FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


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
    return any(
        _decorator_name(decorator) == decorator_name
        for decorator in node.decorator_list
    )


def _is_private_function(function_name: str) -> bool:
    """Return whether a function name is private by convention."""
    return function_name.startswith("_") and not function_name.startswith("__")


def _non_empty_lines(docstring: str) -> list[str]:
    """Return stripped, non-empty lines from a docstring."""
    return [line.strip() for line in docstring.splitlines() if line.strip()]


def _is_one_line_docstring(docstring: str) -> bool:
    """Return whether docstring is a single non-empty line."""
    return len(_non_empty_lines(docstring)) == 1


def _is_sphinx_style(docstring: str) -> bool:
    """Return whether docstring uses Sphinx field directives."""
    return any(SPHINX_FIELD_PATTERN.match(line) for line in docstring.splitlines())


def _validate_sphinx_style(docstring: str) -> list[str]:
    """Validate additional Sphinx-style constraints."""
    errors: list[str] = []
    if any(SPHINX_RTYPE_PATTERN.match(line) for line in docstring.splitlines()):
        errors.append("Sphinx-style docstrings must not include ':rtype:'.")
    return errors


def _next_non_empty_line(lines: list[str], start_index: int) -> tuple[int, str] | None:
    """Return the next non-empty line at or after `start_index`."""
    for index in range(start_index, len(lines)):
        if lines[index]:
            return index, lines[index]
    return None


def _validate_robot_style(docstring: str) -> list[str]:
    """Validate RobotFramework-style sectioned docstring."""
    lines = [line.strip() for line in docstring.splitlines()]
    section_positions: dict[str, int] = {}
    for index, line in enumerate(lines):
        if line in ROBOT_REQUIRED_SECTIONS and line not in section_positions:
            section_positions[line] = index

    errors: list[str] = []
    missing_sections = [
        section
        for section in ROBOT_REQUIRED_SECTIONS
        if section not in section_positions
    ]
    if missing_sections:
        errors.append(
            f"RobotFramework docstring is missing sections: {', '.join(missing_sections)}."
        )
        return errors

    expected_order = [section_positions[section] for section in ROBOT_REQUIRED_SECTIONS]
    if expected_order != sorted(expected_order):
        errors.append(
            "RobotFramework section order must be: Arguments, Returns, Raises, Examples."
        )

    for section in ROBOT_REQUIRED_SECTIONS:
        heading_line = section_positions[section]
        underline_info = _next_non_empty_line(lines, heading_line + 1)
        if underline_info is None:
            errors.append(f"Section '{section}' must contain a dashed underline line.")
            continue

        _, underline = underline_info
        if not re.fullmatch(r"-{3,}", underline):
            errors.append(f"Section '{section}' must contain a dashed underline line.")

    section_boundaries = [
        section_positions[section] for section in ROBOT_REQUIRED_SECTIONS
    ] + [len(lines)]
    for idx, section in enumerate(ROBOT_REQUIRED_SECTIONS):
        section_start = section_boundaries[idx]
        section_end = section_boundaries[idx + 1]
        underline_info = _next_non_empty_line(lines, section_start + 1)
        if underline_info is None:
            continue
        content_start = underline_info[0] + 1
        content_lines = [line for line in lines[content_start:section_end] if line]
        if not content_lines:
            errors.append(
                f"Section '{section}' must contain at least one content line."
            )
            continue

        if section == "Examples:":
            if not any(line.startswith("|") for line in content_lines):
                errors.append(
                    "Section 'Examples:' must include at least one RobotFramework table line."
                )
        else:
            if not any(line.startswith("-") for line in content_lines):
                errors.append(
                    f"Section '{section}' must use bullet lines starting with '-'."
                )

    return errors


def check_function_docstring_style(function_node: FunctionNode) -> list[str]:
    """Check one function node and return style violations."""
    docstring = ast.get_docstring(function_node, clean=True)
    location = f"line {function_node.lineno}, function `{function_node.name}`"

    if not docstring:
        return [f"{location}: missing docstring."]

    is_private = _is_private_function(function_node.name)
    has_keyword = _has_decorator(function_node, "keyword")
    has_not_keyword = _has_decorator(function_node, "not_keyword")

    if has_not_keyword or (is_private and not has_keyword):
        if _is_one_line_docstring(docstring):
            return []
        if _is_sphinx_style(docstring):
            return [
                f"{location}: {error}" for error in _validate_sphinx_style(docstring)
            ]
        return [
            (
                f"{location}: expected one-line or Sphinx-style docstring without ':rtype:' "
                "for private/@not_keyword function."
            )
        ]

    robot_errors = _validate_robot_style(docstring)
    return [f"{location}: {error}" for error in robot_errors]


def check_python_source(source: str, filename: str = "<string>") -> list[str]:
    """Validate all module-level functions in a Python source string."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        line = exc.lineno or 0
        column = exc.offset or 0
        return [f"{filename}:{line}:{column}: unable to parse Python source: {exc.msg}"]

    errors: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            errors.extend(check_function_docstring_style(node))
    return [f"{filename}: {error}" for error in errors]


def check_python_file(file_path: Path) -> list[str]:
    """Validate all module-level function docstrings in a Python file."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{file_path}: unable to read file: {exc}"]
    return check_python_source(source=source, filename=str(file_path))


def _collect_python_files(paths: Iterable[Path]) -> list[Path]:
    """Resolve files from paths and collect Python files recursively."""
    files: set[Path] = set()
    for path in paths:
        if path.is_file() and path.suffix == ".py":
            files.add(path)
            continue
        if path.is_dir():
            files.update(
                candidate for candidate in path.rglob("*.py") if candidate.is_file()
            )
            continue
    return sorted(files)


def check_paths(paths: Sequence[str | Path]) -> list[str]:
    """Validate Python files from provided file or directory paths."""
    normalized_paths = [
        Path(path) if not isinstance(path, Path) else path for path in paths
    ]
    python_files = _collect_python_files(normalized_paths)
    if not python_files:
        joined = ", ".join(str(path) for path in normalized_paths)
        return [f"No Python files found in: {joined}"]

    errors: list[str] = []
    for file_path in python_files:
        errors.extend(check_python_file(file_path))
    return errors


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Validate function docstring style. "
            "Private/@not_keyword functions require one-line or Sphinx style without :rtype:. "
            "Other functions require RobotFramework-style sections."
        )
    )
    parser.add_argument(
        "paths", nargs="+", help="Python file or directory paths to validate."
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run CLI validation and report violations."""
    args = _parse_args(argv)
    errors = check_paths(args.paths)
    if errors:
        for error in errors:
            print(error)
        return 1

    print("No docstring style violations found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
