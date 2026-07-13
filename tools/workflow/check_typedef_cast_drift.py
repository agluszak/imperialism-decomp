"""Audit Hard-Rule-9 typedef-cast scaffolding for signature drift.

Old ports call not-yet-ported functions through per-callsite ``typedef ... (*Name_t)(...)``
casts of generic ``undefined4 Name(void)`` externs. Because every callsite re-declares
its own signature, they drift apart: the same target ends up cast to different
arities/types in different files (which has produced real dropped-argument and
int-passed-as-float bugs; see the 2026-07 mission-scoring cleanup).

This tool extracts every ``<Name>_t`` function-pointer typedef in manual sources,
groups them by target name, and reports:

  * CONFLICT  — one target name declared with more than one (return, args) signature
  * CONVENTION— one target name declared with more than one calling convention

Exit code 1 when conflicts exist (report-only today; not wired into `just gates`).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

from tools.common.file_scan import is_excluded_scan_path

TYPEDEF_RE = re.compile(
    r"typedef\s+(?P<ret>[^;(]*?)\(\s*(?P<conv>__cdecl|__stdcall|__fastcall|__thiscall)?\s*"
    r"\*\s*(?P<name>\w+)_t\s*\)\s*\((?P<args>[^;]*?)\)\s*;",
    re.S,
)


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def strip_param_names(args: str) -> str:
    """Best-effort canonicalization: keep types, drop parameter names."""
    parts = [p.strip() for p in args.split(",")] if args.strip() else []
    out = []
    for part in parts:
        # Drop a trailing identifier if the remainder still names a type.
        m = re.match(r"^(.*?)\s*\b([A-Za-z_]\w*)$", part)
        if m and (
            "*" in m.group(1)
            or m.group(1).strip().split(" ")[-1]
            not in ("", "const", "unsigned", "signed", "long", "short")
        ):
            part = m.group(1).strip() or part
        out.append(normalize(part))
    return ", ".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", default="src/game", help="Source tree to scan (default: src/game)"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Also list non-conflicting cast targets"
    )
    args = parser.parse_args()

    by_name: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    files_of: dict[str, set[str]] = defaultdict(set)
    for path in sorted(Path(args.root).rglob("*.cpp")):
        if is_excluded_scan_path(path):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in TYPEDEF_RE.finditer(text):
            ret = normalize(m.group("ret"))
            conv = m.group("conv") or "(default)"
            sig_args = strip_param_names(m.group("args"))
            by_name[m.group("name")].add((ret, conv, sig_args))
            files_of[m.group("name")].add(path.name)

    conflicts = 0
    conv_conflicts = 0
    for name in sorted(by_name):
        sigs = by_name[name]
        shapes = {(r, a) for r, _, a in sigs}
        convs = {c for _, c, _ in sigs}
        if len(shapes) > 1:
            conflicts += 1
            print(f"CONFLICT   {name}  [{', '.join(sorted(files_of[name]))}]")
            for r, c, a in sorted(sigs):
                print(f"           {r}({c} *)({a})")
        elif len(convs) > 1:
            conv_conflicts += 1
            print(f"CONVENTION {name}  [{', '.join(sorted(files_of[name]))}]")
            for r, c, a in sorted(sigs):
                print(f"           {r}({c} *)({a})")
        elif args.verbose:
            r, c, a = next(iter(sigs))
            print(f"ok         {name}  {r}({c} *)({a})")

    print(
        f"typedef-cast targets: {len(by_name)}; signature conflicts: {conflicts}; "
        f"convention-only conflicts: {conv_conflicts}"
    )
    return 1 if (conflicts or conv_conflicts) else 0


if __name__ == "__main__":
    sys.exit(main())
