# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import pathlib
import re
import unittest

from robot.libdocpkg import LibraryDocumentation

_RF_DIRS = ("tests", "tests_pq_and_hybrid", "tests_mock_ca", "resources", "config")


def _rf_python_libraries() -> set:
    """Return the Python libraries the RF files import, plus `resources/ca_ra_utils.py`."""
    root = pathlib.Path(".").resolve()
    libs = {pathlib.Path("resources/ca_ra_utils.py")}
    for directory in _RF_DIRS:
        for path in root.glob(f"{directory}/**/*"):
            if path.suffix not in (".robot", ".resource"):
                continue
            for lib in re.findall(r"^Library\s+(\S+\.py)", path.read_text(errors="ignore"), re.M):
                libs.add((path.parent / lib).resolve().relative_to(root))
    return libs


class TestValidateCertReqIdKeyword(unittest.TestCase):
    def test_keyword_is_registered_once(self):
        """
        GIVEN every Python library the RF files import, and `resources/ca_ra_utils.py`.
        WHEN listing their RF keywords with libdoc.
        THEN only `resources/checkutils.py` offers `Validate certReqId`.
        """
        offering = sorted(
            str(lib)
            for lib in _rf_python_libraries()
            if "Validate certReqId" in {kw.name for kw in LibraryDocumentation(str(lib)).keywords}
        )
        self.assertEqual(offering, ["resources/checkutils.py"])


if __name__ == "__main__":
    unittest.main()
