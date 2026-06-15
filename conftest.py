# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""Root conftest.py – ensures the project root is on sys.path.

Required so that ``import pq_logic.*`` works when pytest is invoked with a
venv that does not have the package installed in editable mode.
"""

import sys
from pathlib import Path

# Insert the project root (the directory that contains pq_logic/, resources/, …)
# at position 0 so it takes priority over any installed copy.
_project_root = str(Path(__file__).parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# When tests/pq_logic/__init__.py exists, pytest's package-based import mode may
# shadow the real ``pq_logic`` package with the test sub-package.  Evict any
# stale cache entry so the re-import picks up the project-root copy.
_stale = [k for k in sys.modules if k == "pq_logic" or k.startswith("pq_logic.")]
for _k in _stale:
    del sys.modules[_k]
