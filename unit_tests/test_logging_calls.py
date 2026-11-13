# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import ast
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PACKAGES = ("resources", "pq_logic", "mock_ca")
# The `logging` functions and the position of their message argument.
_MSG_INDEX = {"debug": 0, "info": 0, "warning": 0, "error": 0, "critical": 0, "exception": 0, "log": 1}
# A printf-style conversion specifier as `msg % args` reads it; the type "%" is the literal "%%".
_SPECIFIER = re.compile(r"%(?:\([^)]*\))?[#0\- +]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[hlL]?([diouxXeEfFgGcrsa%])")


def _constant_text(node: ast.expr):
    """Return the constant text of a string or f-string node, or `None` for any other node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(part.value for part in node.values if isinstance(part, ast.Constant))
    return None


def _mismatched_logging_calls():
    """Yield `path:line` of every `logging` call whose arguments do not match the placeholders of its message."""
    for package in _PACKAGES:
        for path in sorted((_ROOT / package).rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "logging"
                    and node.func.attr in _MSG_INDEX
                ):
                    continue
                args = node.args[_MSG_INDEX[node.func.attr] :]
                # Without arguments, logging does not format the message.
                if len(args) < 2 or any(isinstance(arg, ast.Starred) for arg in args):
                    continue
                text = _constant_text(args[0])
                if text is None:
                    continue
                specifiers = [kind for kind in _SPECIFIER.findall(text) if kind != "%"]
                if len(specifiers) != len(args) - 1:
                    yield f"{path.relative_to(_ROOT)}:{node.lineno}"


class TestLoggingCalls(unittest.TestCase):
    def test_logging_arguments_match_placeholders(self):
        """
        GIVEN the modules of resources, pq_logic and mock_ca.
        WHEN every `logging` call with a constant message and arguments is parsed.
        THEN the message has one placeholder per argument, because logging formats it with `msg % args`, and a
        mismatch raises `TypeError` and loses the message.
        """
        self.assertEqual(list(_mismatched_logging_calls()), [])


if __name__ == "__main__":
    unittest.main()
