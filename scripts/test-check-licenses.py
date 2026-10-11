"""Negative tests for check-licenses.py.

A license gate that only ever says "clean" is indistinguishable from a
gate that does nothing. These cases pin the decision logic -- especially
the OR/AND distinction, which was a real false positive on `r-efi`
("MIT OR Apache-2.0 OR LGPL-2.1-or-later") before it was handled.

Run: python scripts/test-check-licenses.py
"""

import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_licenses", HERE / "check-licenses.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

# (spdx expression, expected denied token or None)
CASES = [
    # Permissive: must not fire.
    ("MIT", None),
    ("Apache-2.0", None),
    ("MIT OR Apache-2.0", None),
    ("Apache-2.0 OR MIT", None),
    ("MIT/Apache-2.0", None),
    ("Zlib", None),
    ("Unlicense OR MIT", None),
    ("Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT", None),
    ("(MIT OR Apache-2.0) AND Unicode-3.0", None),
    ("MIT AND BSD-3-Clause", None),
    ("Apache-2.0 OR BSL-1.0", None),
    # The real tree contains this one, reachable via rustix/windows-sys.
    # A choice is available, so it is NOT a denial.
    ("MIT OR Apache-2.0 OR LGPL-2.1-or-later", None),
    # Denied: no permissive branch available.
    ("LGPL-2.1-or-later", "LGPL-2.1"),
    ("GPL-3.0-only", "GPL-3.0"),
    ("GPL-2.0", "GPL-2.0"),
    ("AGPL-3.0", "AGPL-3.0"),
    ("SSPL-1.0", "SSPL"),
    # AND forces both, so a denied half cannot be avoided.
    ("MIT AND LGPL-2.1-or-later", "LGPL-2.1"),
    ("MIT AND GPL-3.0", "GPL-3.0"),
    # Every OR branch is denied.
    ("GPL-2.0 OR GPL-3.0", "GPL-2.0"),
    # NOT a denial, and this case is here on purpose: "BSD-3-Clause OR
    # GPL-2.0" offers a clean branch, so we take BSD and the GPL never
    # applies. An earlier draft of this test expected a denial, which was
    # the test being wrong rather than the checker -- the same OR
    # confusion that produced the r-efi false positive, in the opposite
    # direction. Kept as a regression guard.
    ("BSD-3-Clause OR GPL-2.0", None),
]

failures = 0
for expression, expected in CASES:
    actual = module.is_denied(expression)
    ok = actual == expected
    if not ok:
        failures += 1
    status = "PASS" if ok else "FAIL"
    print(f"  {status}  {expression!r} -> {actual!r} (expected {expected!r})")

print(f"{len(CASES) - failures}/{len(CASES)} passed")
raise SystemExit(1 if failures else 0)
