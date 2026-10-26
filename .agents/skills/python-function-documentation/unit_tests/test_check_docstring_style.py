"""Unit tests for the docstring style checker script."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import textwrap
import unittest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "check_docstring_style.py"
)
SPEC = importlib.util.spec_from_file_location("check_docstring_style", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load checker module from {SCRIPT_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _dedent(source: str) -> str:
    return textwrap.dedent(source).strip() + "\n"


class CheckDocstringStyleTests(unittest.TestCase):
    """Validate the rule behavior of check_docstring_style.py."""

    def test_private_one_line_docstring_is_valid(self) -> None:
        source = _dedent(
            """
            def _internal_helper(value: int) -> int:
                \"\"\"Normalize cached value.\"\"\"
                return value
            """
        )

        self.assertEqual(MODULE.check_python_source(source, filename="sample.py"), [])

    def test_private_sphinx_without_rtype_is_valid(self) -> None:
        source = _dedent(
            """
            @not_keyword
            def _internal_helper(value: int) -> int:
                \"\"\"Normalize cached value.

                :param value: Value to normalize.
                :return: Normalized value.
                \"\"\"
                return value
            """
        )

        self.assertEqual(MODULE.check_python_source(source, filename="sample.py"), [])

    def test_private_sphinx_with_rtype_is_invalid(self) -> None:
        source = _dedent(
            """
            @not_keyword
            def _internal_helper(value: int) -> int:
                \"\"\"Normalize cached value.

                :param value: Value to normalize.
                :rtype: int
                :return: Normalized value.
                \"\"\"
                return value
            """
        )

        errors = MODULE.check_python_source(source, filename="sample.py")
        self.assertEqual(len(errors), 1)
        self.assertIn("must not include ':rtype:'", errors[0])

    def test_public_robot_style_is_valid(self) -> None:
        source = _dedent(
            """
            def prepare_example_info_value(fill_value: bool = False) -> int:
                \"\"\"Prepare an example value.

                Arguments:
                ---------
                    - `fill_value`: If `True`, include placeholder data.

                Returns:
                -------
                    - A populated integer value.

                Raises:
                ------
                    - `ValueError`: If preparation fails.

                Examples:
                --------
                | ${value}= | Prepare Example Info Value |
                | ${value}= | Prepare Example Info Value | fill_value=True |

                \"\"\"
                return 1
            """
        )

        self.assertEqual(MODULE.check_python_source(source, filename="sample.py"), [])

    def test_public_one_line_docstring_is_invalid(self) -> None:
        source = _dedent(
            """
            def public_helper(value: int) -> int:
                \"\"\"Simple one-line summary.\"\"\"
                return value
            """
        )

        errors = MODULE.check_python_source(source, filename="sample.py")
        self.assertEqual(len(errors), 1)
        self.assertIn("missing sections", errors[0])

    def test_keyword_requires_robot_style_even_for_private_name(self) -> None:
        source = _dedent(
            """
            @keyword(name="Private Keyword")
            def _private_keyword(value: int) -> int:
                \"\"\"Simple one-line summary.\"\"\"
                return value
            """
        )

        errors = MODULE.check_python_source(source, filename="sample.py")
        self.assertEqual(len(errors), 1)
        self.assertIn("missing sections", errors[0])

    def test_not_keyword_allows_one_line_even_for_public_name(self) -> None:
        source = _dedent(
            """
            @not_keyword
            def public_but_not_keyword(value: int) -> int:
                \"\"\"Simple summary.\"\"\"
                return value
            """
        )

        self.assertEqual(MODULE.check_python_source(source, filename="sample.py"), [])

    def test_syntax_error_returns_single_parse_error(self) -> None:
        source = "def bad(:\n    pass\n"
        errors = MODULE.check_python_source(source, filename="bad.py")
        self.assertEqual(len(errors), 1)
        self.assertIn("unable to parse Python source", errors[0])

    def test_check_paths_directory_collects_python_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            py_file = tmp_path / "good.py"
            py_file.write_text(
                _dedent(
                    """
                    def _helper(value: int) -> int:
                        \"\"\"Normalize value.\"\"\"
                        return value
                    """
                ),
                encoding="utf-8",
            )
            ignored_txt = tmp_path / "notes.txt"
            ignored_txt.write_text("not python", encoding="utf-8")

            errors = MODULE.check_paths([tmp_path])
            self.assertEqual(errors, [])

    def test_check_paths_with_no_python_files_returns_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            readme = tmp_path / "README.md"
            readme.write_text("# no python here\n", encoding="utf-8")

            errors = MODULE.check_paths([tmp_path])
            self.assertEqual(len(errors), 1)
            self.assertIn("No Python files found in:", errors[0])


if __name__ == "__main__":
    unittest.main()
