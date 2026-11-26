# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0
"""Check that test files of ASN.1 builders contain a DER round-trip test.

A round trip is a test function that encodes a structure, decodes it with its spec, and shows that no bytes remain:

- `encoder.encode` or `encode_to_der` or `try_encode_pyasn1`, then
- `decoder.decode` or `try_decode_pyasn1` with a spec, and an assertion that `rest` is empty, or
- `decode_der(data, spec)`, which refuses bytes after the structure itself, so it needs no `rest` assertion.

Exit codes: 0 no violation, 1 a violation, 2 no file matched the pattern.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

DEFAULT_PATTERN = "test_prepare_*.py"
ENCODE_NAMES = frozenset({"encode", "encode_to_der", "try_encode_pyasn1"})
DECODE_NAMES = frozenset({"decode", "try_decode_pyasn1"})  # they return the decoded structure and `rest`
DECODE_DER_NAMES = frozenset({"decode_der"})  # it refuses bytes after the structure
SPEC_KEYWORDS = frozenset({"asn1Spec", "asn1_spec", "spec"})
# `x.encode(...)` and `x.decode(...)` are pyasn1 calls only on the modules `encoder` and `decoder`; any other `x` is
# probably a str or bytes.
PYASN1_MODULES = frozenset({"encoder", "decoder"})

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def _iter_test_nodes(tree: ast.AST) -> list[tuple[str, FunctionNode]]:
    """Return the `test_*` functions and methods with display labels."""
    discovered: list[tuple[str, FunctionNode]] = []
    if not isinstance(tree, ast.Module):
        return discovered

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            discovered.append((node.name, node))
        elif isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and member.name.startswith("test_"):
                    discovered.append((f"{node.name}.{member.name}", member))
    return discovered


def _called_name(call: ast.Call) -> str | None:
    """Return the name of the function that `call` calls, or None if it is not one of the pyasn1 calls.

    `encode(...)`, `encode_to_der(...)` and `module.encode_to_der(...)` give their name. `encoder.encode(...)` and
    `decoder.decode(...)` give `encode` and `decode`; `text.encode(...)` gives None.
    """
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        on_pyasn1_module = isinstance(func.value, ast.Name) and func.value.id in PYASN1_MODULES
        if on_pyasn1_module or func.attr not in {"encode", "decode"}:
            return func.attr
    return None


def _has_spec(call: ast.Call) -> bool:
    """Return whether the decode call gets its spec as keyword or as second positional argument."""
    return any(keyword.arg in SPEC_KEYWORDS for keyword in call.keywords) or len(call.args) >= 2


def _is_rest_assert_call(call: ast.Call) -> bool:
    """Return whether the call asserts that the decoded `rest` is empty."""
    if not isinstance(call.func, ast.Attribute):
        return False

    method = call.func.attr
    if method == "assertFalse" and len(call.args) >= 1:
        return isinstance(call.args[0], ast.Name) and call.args[0].id == "rest"

    if method == "assertEqual" and len(call.args) >= 2:
        left, right = call.args[0], call.args[1]
        left_is_rest = isinstance(left, ast.Name) and left.id == "rest"
        right_is_rest = isinstance(right, ast.Name) and right.id == "rest"
        left_is_empty_bytes = isinstance(left, ast.Constant) and left.value == b""
        right_is_empty_bytes = isinstance(right, ast.Constant) and right.value == b""
        return (left_is_rest and right_is_empty_bytes) or (right_is_rest and left_is_empty_bytes)

    return False


def _analyze_test_node(node: FunctionNode) -> tuple[bool, bool, bool]:
    """Return flags for: encode call, decode call with spec, and proof that no bytes remain."""
    has_encode = False
    has_decode_with_spec = False
    no_rest = False

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = _called_name(child)
        if name in ENCODE_NAMES:
            has_encode = True
        elif name in DECODE_NAMES and _has_spec(child):
            has_decode_with_spec = True
        elif name in DECODE_DER_NAMES and _has_spec(child):
            has_decode_with_spec = True
            no_rest = True
        if _is_rest_assert_call(child):
            no_rest = True

    return has_encode, has_decode_with_spec, no_rest


def check_python_source(source: str, filename: str = "<string>") -> list[str]:
    """Return the violations of one test file: it needs a round-trip test."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [f"{filename}:{exc.lineno or 0}:{exc.offset or 0}: unable to parse Python source: {exc.msg}"]

    test_nodes = _iter_test_nodes(tree)
    if not test_nodes:
        return [f"{filename}: no `test_*` functions found."]

    for _name, node in test_nodes:
        has_encode, has_decode_with_spec, no_rest = _analyze_test_node(node)
        if has_encode and has_decode_with_spec and no_rest:
            return []

    return [
        f"{filename}: missing required round-trip test. Add at least one test_* that encodes the structure "
        "(`encoder.encode`, `encode_to_der`), decodes it with its spec (`decoder.decode(..., asn1Spec=...)` and an "
        "assertion that `rest` is empty, or `decode_der(data, spec)`)."
    ]


def check_python_file(file_path: Path) -> list[str]:
    """Return the violations of one Python file."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{file_path}: unable to read file: {exc}"]
    return check_python_source(source=source, filename=str(file_path))


def collect_test_files(paths: Iterable[Path], pattern: str = DEFAULT_PATTERN) -> list[Path]:
    """Return the files below `paths` (a file or a directory) whose name matches `pattern`."""
    files: set[Path] = set()
    for path in paths:
        candidates = path.rglob("*.py") if path.is_dir() else [path] if path.is_file() else []
        files.update(candidate for candidate in candidates if fnmatch.fnmatch(candidate.name, pattern))
    return sorted(files)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Check that the test files of ASN.1 builders contain a DER round-trip test. "
        "Exit code 2 if no file matches the pattern."
    )
    parser.add_argument("paths", nargs="+", help="Python files or directories to check.")
    parser.add_argument(
        "--pattern",
        default=DEFAULT_PATTERN,
        help="Name pattern of the test files to check (fnmatch); default: %(default)s.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the checker; return 0 for no violation, 1 for a violation, 2 if no file matched the pattern."""
    args = _parse_args(argv)
    files = collect_test_files([Path(path) for path in args.paths], args.pattern)
    if not files:
        sys.stderr.write(f"No file matching {args.pattern} found in: {', '.join(args.paths)}\n")
        return 2

    errors = [error for file_path in files for error in check_python_file(file_path)]
    if errors:
        sys.stdout.write("\n".join(errors) + "\n")
        return 1

    sys.stdout.write(f"{len(files)} files checked, no round-trip violation found.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
