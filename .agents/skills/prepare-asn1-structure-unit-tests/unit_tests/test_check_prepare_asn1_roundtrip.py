"""Unit tests for check_prepare_asn1_roundtrip.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import textwrap
import unittest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "check_prepare_asn1_roundtrip.py"
)
SPEC = importlib.util.spec_from_file_location(
    "check_prepare_asn1_roundtrip", SCRIPT_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load checker module from {SCRIPT_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _source(value: str) -> str:
    return textwrap.dedent(value).strip() + "\n"


class CheckPrepareAsn1RoundtripTests(unittest.TestCase):
    """Validate round-trip checker behavior."""

    def test_valid_roundtrip_with_asn1spec_keyword(self) -> None:
        source = _source(
            """
            class TestPrepareThing:
                def test_prepare_thing_roundtrip(self):
                    data = object()
                    der_data = encoder.encode(data)
                    decoded, rest = decoder.decode(der_data, asn1Spec=SomeSpec())
                    self.assertEqual(rest, b"")
            """
        )
        errors = MODULE.check_python_source(source, filename="test_prepare_thing.py")
        self.assertEqual(errors, [])

    def test_valid_roundtrip_with_positional_spec(self) -> None:
        source = _source(
            """
            def test_prepare_thing_roundtrip():
                value = make_value()
                der_data = encoder.encode(value)
                decoded, rest = decoder.decode(der_data, SomeSpec())
                self.assertFalse(rest)
            """
        )
        errors = MODULE.check_python_source(source, filename="test_prepare_thing.py")
        self.assertEqual(errors, [])

    def test_valid_roundtrip_with_direct_encode_decode_imports(self) -> None:
        source = _source(
            """
            def test_prepare_thing_roundtrip():
                value = make_value()
                der_data = encode(value)
                decoded, rest = decode(der_data, SomeSpec())
                self.assertEqual(rest, b"")
            """
        )
        errors = MODULE.check_python_source(source, filename="test_prepare_thing.py")
        self.assertEqual(errors, [])

    def test_missing_roundtrip_is_reported(self) -> None:
        source = _source(
            """
            class TestPrepareThing:
                def test_prepare_thing_fields(self):
                    self.assertTrue(True)
            """
        )
        errors = MODULE.check_python_source(source, filename="test_prepare_thing.py")
        self.assertEqual(len(errors), 1)
        self.assertIn("missing required round-trip test", errors[0])

    def test_decode_without_spec_is_reported(self) -> None:
        source = _source(
            """
            def test_prepare_thing_roundtrip():
                data = encoder.encode(build_value())
                decoded, rest = decoder.decode(data)
                self.assertEqual(rest, b"")
            """
        )
        errors = MODULE.check_python_source(source, filename="test_prepare_thing.py")
        self.assertEqual(len(errors), 1)
        self.assertIn("missing required round-trip test", errors[0])

    def test_missing_rest_assert_is_reported(self) -> None:
        source = _source(
            """
            def test_prepare_thing_roundtrip():
                data = encoder.encode(build_value())
                decoded, rest = decoder.decode(data, asn1Spec=SomeSpec())
                self.assertTrue(decoded.isValue)
            """
        )
        errors = MODULE.check_python_source(source, filename="test_prepare_thing.py")
        self.assertEqual(len(errors), 1)
        self.assertIn("missing required round-trip test", errors[0])

    def test_non_prepare_file_is_ignored(self) -> None:
        source = _source(
            """
            def test_anything():
                pass
            """
        )
        errors = MODULE.check_python_source(source, filename="test_certutils.py")
        self.assertEqual(errors, [])

    def test_syntax_error_is_reported(self) -> None:
        errors = MODULE.check_python_source(
            "def bad(:\n    pass\n", filename="test_prepare_bad.py"
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("unable to parse Python source", errors[0])

    def test_check_paths_with_no_python_files_returns_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "README.md").write_text("# no python here\n", encoding="utf-8")
            errors = MODULE.check_paths([tmp_path])
            self.assertEqual(len(errors), 1)
            self.assertIn("No Python files found in:", errors[0])


if __name__ == "__main__":
    unittest.main()
