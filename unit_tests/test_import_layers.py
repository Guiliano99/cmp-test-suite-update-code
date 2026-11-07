# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import ast
import pathlib
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PACKAGES = ("resources", "pq_logic", "mock_ca")

# The target layering, lowest first. A module may import its own layer and lower ones, never a higher one.
# A name ending in ".*" stands for a package and every module in it.
LAYERS = [
    [
        "resources",  # empty package marker
        "pq_logic",  # empty package marker
        "resources.exceptions",
        "resources.typingutils",
        "resources.asn1_structures",
        "resources.oidutils",
        "resources.oid_mapping",
        "resources.copyasn1utils",
        "resources.convertutils",
        "resources.asn1utils",
        "resources.suiteenums",
        "resources.data_objects",
        "resources.prepare_alg_ids",
        "pq_logic.tmp_oids",
        "pq_logic.hybrid_structures",
        "pq_logic.pq_utils",
    ],
    ["resources.utils"],
    ["resources.keyutils", "resources.cryptoutils"],
    [
        "resources.prepareutils",
        "resources.certextractutils",
        "resources.compareutils",
        "resources.certutils",
        "resources.certbuildutils",
        "resources.deprecatedutils",
        "resources.cert_linters_utils",
        "pq_logic.hybrid_sig.*",
    ],
    ["resources.envdatautils"],
    [
        "resources.cmputils",
        "resources.protectionutils",
        "resources.checkutils",
        "pq_logic.pq_verify_logic",
        "resources.general_msg_utils",
        "resources.extra_issuing_logic",
        "resources.ca_ra_utils",
        "pq_logic.hybrid_issuing",
        "resources.announcement",
        "resources.httputils",
        "pq_logic.hybrid_prepare",
        "resources.cert_related_utils",
        # ca_kga_logic mixes CMS and CMP rules, so it sits at the CMP level until it is split.
        "resources.ca_kga_logic",
    ],
    ["mock_ca.*"],
]

# (importing module, imported module) -> reason, for the upward imports that remain. It may only shrink:
# an entry whose import no longer exists fails the test.
ALLOWED = {}


def _layer(module):
    """Return the layer of a dotted module name, or None if no layer lists it."""
    for level, names in enumerate(LAYERS):
        for name in names:
            if module == name.removesuffix(".*") or (name.endswith(".*") and module.startswith(name[:-1])):
                return level
    return None


def _modules():
    """Parse every module in the production packages, keyed by dotted name."""
    modules = {}
    for package in _PACKAGES:
        for path in sorted((_ROOT / package).rglob("*.py")):
            name = ".".join(path.relative_to(_ROOT).with_suffix("").parts).removesuffix(".__init__")
            modules[name] = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return modules


def _imports(tree, modules):
    """Yield (line, imported name) for every import in a tree, at module level or inside a function.

    `from package import name` yields `package.name` if that is a module, otherwise `package`.
    A relative import yields its leading dots, so the caller can reject it.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            for alias in node.names:
                full = f"{module}.{alias.name}"
                yield node.lineno, full if full in modules else module


class TestImportLayers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = _modules()
        cls.upward = {}
        cls.relative = []
        for name, tree in cls.modules.items():
            source_level = _layer(name)
            for line, target in _imports(tree, cls.modules):
                target_level = _layer(target)
                if target.startswith("."):
                    cls.relative.append(f"{name}:{line} {target}")
                elif None not in (source_level, target_level) and target_level > source_level:
                    cls.upward.setdefault((name, target), []).append(line)

    def test_every_module_has_a_layer(self):
        """
        GIVEN every module in resources/, pq_logic/ and mock_ca/.
        WHEN looking up its layer,
        THEN every module must have one, so a new module cannot escape the layer check.
        """
        missing = [name for name in self.modules if _layer(name) is None]
        self.assertEqual(missing, [], "Add these modules to LAYERS.")

    def test_no_upward_imports(self):
        """
        GIVEN every import in resources/, pq_logic/ and mock_ca/, at module level or inside a function.
        WHEN comparing the layer of the importing module with the layer of the imported one,
        THEN no module imports a higher layer, except for the edges in ALLOWED.
        """
        violations = [
            f"{name} (L{_layer(name)}) imports {target} (L{_layer(target)}) at lines {lines}"
            for (name, target), lines in sorted(self.upward.items())
            if (name, target) not in ALLOWED
        ]
        self.assertEqual(violations, [])
        self.assertEqual(self.relative, [], "Use absolute imports, so the layer check can resolve them.")

    def test_allowed_edges_still_exist(self):
        """
        GIVEN the upward imports in ALLOWED.
        WHEN looking for them in the code,
        THEN each one must still exist, so the list can only shrink.
        """
        stale = sorted(edge for edge in ALLOWED if edge not in self.upward)
        self.assertEqual(stale, [], "Remove these edges from ALLOWED.")

    def test_no_production_module_imports_unit_tests(self):
        """
        GIVEN every import in resources/, pq_logic/ and mock_ca/.
        WHEN looking for the unit_tests package,
        THEN no production module imports it.
        """
        found = [
            f"{name}:{line} {target}"
            for name, tree in self.modules.items()
            for line, target in _imports(tree, self.modules)
            if target.split(".")[0] == "unit_tests"
        ]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
