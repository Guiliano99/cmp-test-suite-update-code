#!/usr/bin/env python3
"""Validate presence of DER encode/decode round-trip tests in prepare ASN.1 test files."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
from typing import Iterable, Sequence

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def _is_prepare_test_file(filename: str) -> bool:
    """Return whether the file name targets prepare ASN.1 tests."""
    return Path(filename).name.startswith("test_prepare_")


def _iter_test_nodes(tree: ast.AST) -> list[tuple[str, FunctionNode]]:
    """Return discovered `test_*` functions/methods with display labels."""
    discovered: list[tuple[str, FunctionNode]] = []
    if not isinstance(tree, ast.Module):
        return discovered

    for node in tree.body:
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) and node.name.startswith("test_"):
            discovered.append((node.name, node))
            continue

        if isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(
                    member, (ast.FunctionDef, ast.AsyncFunctionDef)
                ) and member.name.startswith("test_"):
                    discovered.append((f"{node.name}.{member.name}", member))
    return discovered


def _is_encoder_encode_call(call: ast.Call) -> bool:
    """Return whether call is `encoder.encode(...)` or imported `encode(...)`."""
    if isinstance(call.func, ast.Name):
        return call.func.id == "encode"
    return (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "encoder"
        and call.func.attr == "encode"
    )


def _is_decoder_decode_call(call: ast.Call) -> bool:
    """Return whether call is `decoder.decode(...)` or imported `decode(...)`."""
    if isinstance(call.func, ast.Name):
        return call.func.id == "decode"
    return (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "decoder"
        and call.func.attr == "decode"
    )


def _decode_has_asn1_spec(call: ast.Call) -> bool:
    """Return whether `decoder.decode` call provides ASN.1 spec via kwarg or positional arg."""
    has_kw_spec = any(keyword.arg == "asn1Spec" for keyword in call.keywords)
    has_positional_spec = len(call.args) >= 2
    return has_kw_spec or has_positional_spec


def _is_rest_assert_call(call: ast.Call) -> bool:
    """Return whether call asserts decoded `rest` is empty."""
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
        return (left_is_rest and right_is_empty_bytes) or (
            right_is_rest and left_is_empty_bytes
        )

    return False


def _analyze_test_node(node: FunctionNode) -> tuple[bool, bool, bool]:
    """Return flags for encode usage, decode+spec usage, and rest assertion."""
    has_encode = False
    has_decode_with_spec = False
    has_rest_assert = False

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if _is_encoder_encode_call(child):
                has_encode = True
            if _is_decoder_decode_call(child) and _decode_has_asn1_spec(child):
                has_decode_with_spec = True
            if _is_rest_assert_call(child):
                has_rest_assert = True

    return has_encode, has_decode_with_spec, has_rest_assert


def check_python_source(source: str, filename: str = "<string>") -> list[str]:
    """Validate one Python source string for required round-trip test coverage."""
    if not _is_prepare_test_file(filename):
        return []

    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        line = exc.lineno or 0
        column = exc.offset or 0
        return [f"{filename}:{line}:{column}: unable to parse Python source: {exc.msg}"]

    test_nodes = _iter_test_nodes(tree)
    if not test_nodes:
        return [f"{filename}: no `test_*` functions found in prepare test file."]

    has_required_roundtrip = False
    for _name, node in test_nodes:
        has_encode, has_decode_with_spec, has_rest_assert = _analyze_test_node(node)
        if has_encode and has_decode_with_spec and has_rest_assert:
            has_required_roundtrip = True
            break

    if has_required_roundtrip:
        return []

    return [
        (
            f"{filename}: missing required round-trip test. Add at least one test_* using "
            "`encoder.encode`, `decoder.decode(..., asn1Spec=...)` (or second positional spec), "
            "and an assertion that `rest` is empty."
        )
    ]


def check_python_file(file_path: Path) -> list[str]:
    """Validate one Python file."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{file_path}: unable to read file: {exc}"]
    return check_python_source(source=source, filename=str(file_path))


def _collect_python_files(paths: Iterable[Path]) -> list[Path]:
    """Collect Python files from files/directories."""
    files: set[Path] = set()
    for path in paths:
        if path.is_file() and path.suffix == ".py":
            files.add(path)
            continue
        if path.is_dir():
            files.update(
                candidate for candidate in path.rglob("*.py") if candidate.is_file()
            )
    return sorted(files)


def check_paths(paths: Sequence[str | Path]) -> list[str]:
    """Validate round-trip requirements for supplied paths."""
    normalized = [Path(path) if not isinstance(path, Path) else path for path in paths]
    python_files = _collect_python_files(normalized)
    if not python_files:
        joined = ", ".join(str(path) for path in normalized)
        return [f"No Python files found in: {joined}"]

    errors: list[str] = []
    for file_path in python_files:
        errors.extend(check_python_file(file_path))
    return errors


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Validate prepare ASN.1 test files include at least one DER round-trip test: "
            "encoder.encode + decoder.decode(asn1Spec) + rest-empty assertion."
        )
    )
    parser.add_argument(
        "paths", nargs="+", help="Python file or directory paths to validate."
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run CLI checker."""
    args = _parse_args(argv)
    errors = check_paths(args.paths)
    if errors:
        for error in errors:
            print(error)
        return 1

    print("No prepare ASN.1 round-trip violations found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
