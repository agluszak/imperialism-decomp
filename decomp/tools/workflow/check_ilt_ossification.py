#!/usr/bin/env python3
"""Hard-ban gate against ILT / thunk-name ossification in manual source.

Two related smells keep linker- and decompiler-implementation detail alive in
hand-written game source, and both must stay at zero:

1. **Calls via ILT.** An incremental-link thunk (``thunk_Foo`` / ``ILT_Foo`` at a
   ``0x004xxxxx`` address) is a 5-byte ``jmp`` to the real body, never a source
   function. Manual code that declares or calls ``thunk_Foo`` keeps the generated
   stub row alive, which keeps the manual call compilable — a self-sustaining cycle.
   The fix is to call the real target (resolve the jmp with ``just ghidra listing
   0xADDR`` or ``just ghidra portprep``) and drop the thunk row.

2. **History-encoded names.** A real body whose name is ``WrapperFor_thunk_Foo_At0049d900``
   or ``Foo_At004f6d90`` leaks the discovery path (an intermediate thunk name + the
   raw address) into the source-level API. Rename to the semantic role, or — when the
   role is unknown — a neutral ``<Owner>Slot<NN>`` / ``Function_004xxxxx`` name, with
   the address living only in the ``// FUNCTION:`` marker.

This gate flags any identifier in manual source (``src/game``, ``include/game``) that
- begins with ``thunk_`` or ``ILT_``,
- begins with ``WrapperFor_``, or
- ends with ``_At<8 hex digits>``,
outside of comments. This is a baseline-free HARD BAN: the debt was fully eradicated,
so ANY offender fails -- there is no baseline file and no update escape hatch. A new
offender is always a source defect to fix (call the real target / use a semantic name).

Generated trees (``src/ghidra_autogen``, ``src/autogen``, ``include/ghidra_autogen``)
are out of scope here; they are tool-owned and cleaned by the resync pipeline.
"""

from __future__ import annotations

import argparse
import re

from tools.common.file_scan import iter_files
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

DEFAULT_PATHS = ("include/game", "src/game")

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paths", nargs="+", default=list(DEFAULT_PATHS))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    offenders = sorted(collect_offenders(args.paths, repo_root))

    if offenders:
        print("ILT-ossification gate failed (hard ban): linker/thunk-name identifier(s) in manual source.")
        print("Call the real target (resolve the thunk via just ghidra portprep) or use a semantic/slot name;")
        print("the address belongs only in the // FUNCTION: marker.")
        print("This is a hard ban with no baseline: fix the source, do not bless it.")
        for rel, ident in offenders:
            print(f"    - {rel}: {ident}")
        return 1

    print("ILT-ossification gate passed (hard ban -- zero offenders).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
