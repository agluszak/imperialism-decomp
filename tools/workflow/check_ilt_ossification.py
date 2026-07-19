#!/usr/bin/env python3
"""Ratchet gate against ILT / thunk-name ossification in manual source.

Two related smells keep linker- and decompiler-implementation detail alive in
hand-written game source, and both must shrink to zero:

1. **Calls via ILT.** An incremental-link thunk (``thunk_Foo`` / ``ILT_Foo`` at a
   ``0x004xxxxx`` address) is a 5-byte ``jmp`` to the real body, never a source
   function. Manual code that declares or calls ``thunk_Foo`` keeps the generated
   stub row alive, which keeps the manual call compilable — a self-sustaining cycle.
   The fix is to call the real target (resolve via ``docs/ilt_target_map.csv``) and
   drop the thunk row.

2. **History-encoded names.** A real body whose name is ``WrapperFor_thunk_Foo_At0049d900``
   or ``Foo_At004f6d90`` leaks the discovery path (an intermediate thunk name + the
   raw address) into the source-level API. Rename to the semantic role, or — when the
   role is unknown — a neutral ``<Owner>Slot<NN>`` / ``Function_004xxxxx`` name, with
   the address living only in the ``// FUNCTION:`` marker.

This gate flags any identifier in manual source (``src/game``, ``include/game``) that
- begins with ``thunk_`` or ``ILT_``,
- begins with ``WrapperFor_``, or
- ends with ``_At<8 hex digits>``,
outside of comments. It is a **ratchet**: existing offenders are grandfathered by
``config/baselines/ilt_ossification_baseline.csv`` (keyed by file + identifier, so line moves
don't matter); a NEW offender fails the gate, and clearing an offender lets you
``--write-baseline`` to shrink the queue. The goal is a strictly-decreasing baseline.

Generated trees (``src/ghidra_autogen``, ``src/autogen``, ``include/ghidra_autogen``)
are out of scope here; they are tool-owned and cleaned by the resync pipeline.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import iter_files
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

DEFAULT_PATHS = ("include/game", "src/game")
DEFAULT_BASELINE = "config/baselines/ilt_ossification_baseline.csv"

IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_AT_SUFFIX_RE = re.compile(r"_At[0-9A-Fa-f]{8}$")


def is_ossified(identifier: str) -> bool:
    if identifier.startswith(("thunk_", "ILT_", "WrapperFor_")):
        return True
    return bool(_AT_SUFFIX_RE.search(identifier))


def strip_line_comment(line: str) -> str:
    """Drop a ``//`` line comment. Naive (no string/`/* */` handling) — sufficient for
    these headers/TUs, where the banned identifiers never live inside string literals."""
    idx = line.find("//")
    return line[:idx] if idx >= 0 else line


def collect_offenders(paths, repo_root) -> set[tuple[str, str]]:
    offenders: set[tuple[str, str]] = set()
    for path in iter_files(paths):
        rel = normalize_repo_relative_path(path, repo_root)
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            code = strip_line_comment(line)
            for ident in IDENT_RE.findall(code):
                if is_ossified(ident):
                    offenders.add((rel, ident))
    return offenders


def read_baseline(path: Path) -> set[tuple[str, str]]:
    if not path.is_file():
        return set()
    out: set[tuple[str, str]] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line == "path|identifier":
            continue
        rel, _, ident = line.partition("|")
        if rel and ident:
            out.add((rel.strip(), ident.strip()))
    return out


def write_baseline(path: Path, offenders: set[tuple[str, str]]) -> None:
    lines = ["path|identifier"]
    lines += [f"{rel}|{ident}" for rel, ident in sorted(offenders)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paths", nargs="+", default=list(DEFAULT_PATHS))
    parser.add_argument("--baseline", default=str(repo_root / DEFAULT_BASELINE))
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Rewrite the baseline from the current offenders (ratchet down after a "
        "migration). Never run this to silence a NEW offender.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    baseline_path = Path(args.baseline)

    offenders = collect_offenders(args.paths, repo_root)

    if args.write_baseline:
        write_baseline(baseline_path, offenders)
        print(f"Wrote ILT-ossification baseline: {baseline_path} ({len(offenders)} offender(s))")
        return 0

    baseline = read_baseline(baseline_path)
    new = sorted(offenders - baseline)
    resolved = sorted(baseline - offenders)

    print(f"ILT-ossification offenders: {len(offenders)} (baseline {len(baseline)})")
    if resolved:
        print(f"  {len(resolved)} baselined offender(s) resolved — run --write-baseline to shrink:")
        for rel, ident in resolved[:20]:
            print(f"    - {rel}: {ident}")

    if new:
        print("ILT-ossification gate failed: new linker/thunk-name identifier(s) in manual source.")
        print("Call the real target (docs/ilt_target_map.csv) or use a semantic/slot name;")
        print("the address belongs only in the // FUNCTION: marker.")
        for rel, ident in new:
            print(f"    - {rel}: {ident}")
        return 1

    print("ILT-ossification gate passed (no new offenders).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
