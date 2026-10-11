#!/usr/bin/env python3
"""Check the licenses of every crate in the resolved dependency tree.

Why this exists
---------------
`cargo-deny` would do this, but it needs its own network fetch and a
separate toolchain install, and this repo already requires every gate to
run offline through `scripts/cargo.ps1`. This script gets the same answer
out of `cargo metadata --all-features`, which is already local.

The rule is a DENY list, not an allow list. An allow list would fail the
build the first time a crate uses a license string we forgot to enumerate
("MIT/Apache-2.0" vs "MIT OR Apache-2.0" vs "Apache-2.0 WITH
LLVM-exception"), and a gate that cries wolf gets switched off -- which
is worse than not having it. Denying the specific licenses that would
force this project open-sourced is the property we actually care about.

Exit codes: 0 = clean, 1 = a denied license is present, 2 = could not run.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

# Licenses that would infect the whole product. These are the only hard
# failures. Anything else is reported for information but does not block.
#
# Ordered longest-prefix-first: "AGPL-3.0" must be tested before "GPL-3.0",
# and "LGPL-3.0" before "GPL-3.0", because the shorter token is a substring
# of the longer one. Without the ordering a bare "AGPL-3.0" still gets
# denied, but it is reported as "GPL-3.0" -- right verdict, wrong
# identifier, and the identifier is what a human uses to find the remedy.
DENIED = (
    "AGPL-3.0",
    "LGPL-3.0",
    "LGPL-2.1",
    "GPL-3.0",
    "GPL-2.0",
    "SSPL",
)

# Crates known to be denied upstream. Listing them by name turns "someone
# added a dep and it happened to be GPL" into a message that names the
# crates we deliberately rejected, so the next person does not re-propose
# one of them. They are NOT special-cased in the check itself -- the
# license match is what fails the build.
KNOWN_BAD = {
    "exe": "PE 解析；GPL-3.0。替代品：自研或 object/goblin",
    "dotnetdll": ".NET metadata；GPL-3.0+。替代品：dotscope (Apache-2.0)",
    "smali": "DEX；GPL-3.0-only。替代品：无（需自研）",
    "lief": "构建期联网下载预编译二进制（许可本身是 Apache-2.0，理由是工程性的）",
    "jingle_sleigh": "编译 13k 行 C++，破坏单文件可执行",
    "sleigh-compiler": "111k 行 C++ 对 149 行 Rust，最差 FFI 比例",
}


def cargo_metadata() -> dict:
    cargo = os.environ.get("CARGO", "cargo")
    proc = subprocess.run(
        [cargo, "metadata", "--format-version", "1", "--all-features"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        sys.stderr.write("cargo metadata failed:\n" + (proc.stderr or "")[:2000])
        raise SystemExit(2)
    return json.loads(proc.stdout)


def license_of(pkg: dict) -> str:
    # `license` is the SPDX expression; `license_file` means the crate
    # ships a file without declaring an expression. Neither is "unknown"
    # for our purposes -- but a package with BOTH empty is, and that must
    # be visible rather than silently counted as fine.
    expr = (pkg.get("license") or "").strip()
    if expr:
        return expr
    if pkg.get("license_file"):
        return f"<file:{pkg['license_file']}>"
    return ""


def is_denied(expr: str) -> str | None:
    """Return the matched denied token, or None.

    The rule is about *choice*, not about the raw string. An SPDX
    expression is a sum of products: `A OR B` is satisfied by picking
    either, `A AND B` requires both. A denial therefore bites only when
    some choice leads to a denied license.

      "MIT OR LGPL-2.1-or-later"   -> fine, we pick MIT
      "MIT AND LGPL-2.1-or-later"  -> DENIED, both are required
      "LGPL-2.1-or-later"          -> DENIED, it is the only option
      "BSD-3-Clause OR GPL-2.0"    -> DENIED, the other branch is denied too

    A first version matched the raw substring and flagged `r-efi`
    ("MIT OR Apache-2.0 OR LGPL-2.1-or-later", reachable through
    `rustix`/`windows-sys`). That was a false positive. A second version
    cleared an alternative whenever *any* of its AND-ed tokens was
    permissive, which wrongly whitewashed a bare "LGPL-2.1-or-later"
    (a single AND-ed term that IS the whole expression).
    The tests in `test-check-licenses.py` pin both directions.
    """
    # Split on OR: each alternative is an independent way to satisfy the
    # expression, so we only need one clean alternative.
    #
    # The separators are written with required surrounding WHITESPACE, not
    # \b. Word boundaries are wrong here because SPDX has hyphenated ids
    # that contain these very words: `LGPL-2.1-or-later` was being split
    # into `LGPL-2.1-` + `-later`, which silently dropped the denial and
    # made the gate pass a bare LGPL expression. In real SPDX text the
    # operators are always whitespace-separated.
    alternatives = [a for a in re.split(r"\s+OR\s+", expr, flags=re.IGNORECASE) if a.strip()]
    if not alternatives:
        return None

    for alternative in alternatives:
        # An alternative is a conjunction (`WITH` binds like AND: the
        # exception is part of one combined option).
        terms = [
            t
            for t in re.split(r"\s+AND\s+|\s+WITH\s+", alternative, flags=re.IGNORECASE)
            if t.strip()
        ]
        if not terms:
            continue
        # This alternative is viable only if EVERY term is acceptable.
        hits = [h for h in (_denied_token(t) for t in terms) if h]
        if not hits:
            return None

    # No alternative survives. Report the first denial we can name, in the
    # order the expression lists them, so the message points at the actual
    # dependency's wording rather than an arbitrary reordering.
    for alternative in alternatives:
        for term in re.split(r"\s+AND\s+|\s+WITH\s+", alternative, flags=re.IGNORECASE):
            hit = _denied_token(term)
            if hit:
                return hit
    return None


def _denied_token(text: str) -> str | None:
    """Match one SPDX license id (possibly with /+/-only/-or-later)."""
    cleaned = text.strip()
    if not cleaned:
        return None
    upper = cleaned.upper()
    for token in DENIED:
        if token.upper() in upper:
            return token
    return None


def main() -> int:
    meta = cargo_metadata()
    packages = meta.get("packages", [])
    workspace = set(meta.get("workspace_members", []))

    denied: list[tuple[str, str, str, str]] = []
    unknown: list[tuple[str, str]] = []
    seen: dict[str, str] = {}

    for pkg in packages:
        name = pkg.get("name", "?")
        version = pkg.get("version", "?")
        expr = license_of(pkg)
        if not expr:
            unknown.append((name, version))
            continue
        seen[name] = expr
        hit = is_denied(expr)
        if hit:
            denied.append((name, version, expr, hit))

    print(f"checked {len(packages)} package(s) in the resolved tree")

    if unknown:
        # Not a failure: a crate may legitimately ship only a LICENSE file,
        # and we cannot read every vendored file cheaply. But it must be
        # counted out loud, because "0 denied" means nothing if half the
        # tree was skipped (CLAUDE.md section 7: a silent skip is a lie).
        print(f"  WARNING: {len(unknown)} package(s) declare no license expression:")
        for name, version in sorted(unknown)[:10]:
            print(f"    {name} {version}")
        if len(unknown) > 10:
            print(f"    ... and {len(unknown) - 10} more")

    if denied:
        print("")
        print("DENIED license(s) present -- these would force this project open:")
        for name, version, expr, hit in sorted(denied):
            print(f"  {name} {version}: {expr}  (matched {hit})")
            if name in KNOWN_BAD:
                print(f"    note: {KNOWN_BAD[name]}")
        # Naming every known-bad crate, not just the ones found, is the
        # point: it is the list a reviewer needs when a PR proposes one.
        print("")
        print("  previously-rejected crates to watch for:")
        for name, why in sorted(KNOWN_BAD.items()):
            if name not in seen:
                print(f"    {name}: {why}")
        return 1

    counts: dict[str, int] = {}
    for expr in seen.values():
        counts[expr] = counts.get(expr, 0) + 1
    print("  license distribution:")
    for expr, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"    {n:4d}  {expr}")

    print("no denied licenses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
