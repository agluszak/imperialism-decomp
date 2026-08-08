#!/usr/bin/env python3
"""Attach FUNCTION markers to ordinary destructors called by scalar deleting dtors.

The 363 scalar deleting destructors pinned at exactly 90.91% all share one diff
line: `call <OFFSETn>` — the ordinary destructor they call has no original-side
entity, so reccmp cannot resolve the operand. Our side already emits the right
`??1Class` body (header-inline or out-of-line `Class::~Class() {}`); the only
missing piece is claiming the original address on that definition.

For each below-100% `Class::`scalar deleting destructor'` baseline row this tool:

1. reads the ``??_G`` body from the original binary and decodes its first
   ``call rel32`` (chasing one ILT ``jmp`` hop) to find the ordinary destructor
   address;
2. locates the class's destructor *definition* in manual source — an out-of-line
   ``Class::~Class(`` in ``src/game`` or an inline ``~Class(...) ... {`` in
   ``include/game`` — per the destructor-placement gate's ``inline_proven`` shape;
3. inserts ``// FUNCTION: IMPERIALISM 0x00ADDR`` immediately above the definition
   (Hard Rule 3), unless the address is already claimed anywhere in the tree.

Classes with no manual definition (MFC/library or unrecovered) and duplicate
call targets (COMDAT-folded bodies) are reported, never guessed at.

A claimed address whose original bytes are a bare ``jmp`` (an incremental-link
"moved function" island, chaining ILT -> island -> ILT -> body) is CORRECT and
must not be re-homed to the chain's final body: the shipped binary was linked
incrementally by LINK 5.0 and folded/aliased dozens of leaf destructors into a
few shared base bodies (e.g. many leaf views -> TView::~TView at 0x48a9d0).
The island is the symbol's canonical address; claiming it under the class's
own name is what lets reccmp resolve the ??_G caller's call operand per class
(chasing stops at the first named node). Such rows score ~0% individually —
that is the honest per-address comparison of our real body against a 5-byte
stub, and the reason the repo-average dips while exact counts rise.

Dry-run by default; pass --apply to edit files.
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE = REPO_ROOT / "config/baselines/reccmp_progress_baseline.functions.csv"
SCALAR_SUFFIX = "::`scalar deleting destructor'"
ILT_LO, ILT_HI = 0x401000, 0x409AB5
MARKER_RE = re.compile(r"//\s*(?:FUNCTION|SYNTHETIC|TEMPLATE|LIBRARY|STUB):\s*IMPERIALISM\s+0x")


class Pe:
    def __init__(self, path: Path) -> None:
        self.data = path.read_bytes()
        pe_off = struct.unpack_from("<I", self.data, 0x3C)[0]
        nsec = struct.unpack_from("<H", self.data, pe_off + 6)[0]
        opt_size = struct.unpack_from("<H", self.data, pe_off + 20)[0]
        self.base = struct.unpack_from("<I", self.data, pe_off + 24 + 28)[0]
        sec0 = pe_off + 24 + opt_size
        self.sections = []
        for i in range(nsec):
            s = sec0 + i * 40
            vsize, vaddr, rawsize, praw = struct.unpack_from("<IIII", self.data, s + 8)
            self.sections.append((vaddr, max(vsize, rawsize), praw))

    def va2off(self, va: int) -> int:
        rva = va - self.base
        for vaddr, vsize, praw in self.sections:
            if vaddr <= rva < vaddr + vsize:
                return praw + (rva - vaddr)
        raise ValueError(f"va 0x{va:08x} not in any section")

    def read(self, va: int, n: int) -> bytes:
        off = self.va2off(va)
        return self.data[off : off + n]


def parse_env_binary() -> Path:
    env = REPO_ROOT / ".env"
    for line in env.read_text().splitlines():
        if line.startswith("ORIGINAL_BINARY="):
            return Path(line.split("=", 1)[1].strip().strip('"'))
    raise SystemExit("ORIGINAL_BINARY not set in .env")


def scalar_dtor_rows() -> list[tuple[int, float, str]]:
    rows = []
    for line in BASELINE.read_text().splitlines()[1:]:
        addr_s, matching_s, name = line.split("|", 2)
        if not name.endswith(SCALAR_SUFFIX):
            continue
        matching = float(matching_s)
        if matching >= 1.0:
            continue
        rows.append((int(addr_s, 16), matching, name[: -len(SCALAR_SUFFIX)]))
    return rows


ALIASES_CSV = REPO_ROOT / "config/template_aliases.csv"


def island_dtor_rows() -> list[tuple[int, str]]:
    """(island_address, class) from folded_symbol_group alias rows whose name
    is a destructor (``Class::~Class``). These are the incremental-link fold
    islands enumerated by `just stale-jmp-islands` — each island is the leaf
    class's canonical ordinary-destructor address, claimable directly without
    decoding a ??_G caller (bd iftm)."""
    rows: list[tuple[int, str]] = []
    for line in ALIASES_CSV.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]  # pipe-split-ok: commented table
        if len(parts) != 4 or parts[3] != "folded_symbol_group":
            continue
        m = re.fullmatch(r"(\w+)::~(\w+)", parts[2])
        if not m or m.group(1) != m.group(2):
            continue
        rows.append((int(parts[0], 16), m.group(1)))
    return rows


def decode_dtor_target(pe: Pe, gaddr: int) -> int | None:
    """First `call rel32` within the ??_G body, chased through one ILT jmp hop."""
    body = pe.read(gaddr, 16)
    idx = body.find(b"\xE8")
    if idx < 0:
        return None
    rel = struct.unpack_from("<i", body, idx + 1)[0]
    target = gaddr + idx + 5 + rel
    if ILT_LO <= target <= ILT_HI:
        thunk = pe.read(target, 5)
        if thunk[0] != 0xE9:
            return None
        rel = struct.unpack_from("<i", thunk, 1)[0]
        target = target + 5 + rel
    return target


def collect_claimed_addresses() -> set[int]:
    claimed: set[int] = set()
    pat = re.compile(r"IMPERIALISM\s+0x([0-9a-fA-F]{6,8})")
    for root in ("src", "include"):
        for path in (REPO_ROOT / root).rglob("*.[ch]*"):
            if path.suffix not in (".cpp", ".h"):
                continue
            for m in pat.finditer(path.read_text(errors="replace")):
                claimed.add(int(m.group(1), 16))
    return claimed


def find_definition(cls: str) -> tuple[Path, int] | None:
    """(file, 0-based line index) of the destructor DEFINITION for `cls`."""
    out_of_line = re.compile(rf"^\s*{re.escape(cls)}::~{re.escape(cls)}\s*\(")
    for path in sorted((REPO_ROOT / "src/game").rglob("*.cpp")):
        lines = path.read_text(errors="replace").splitlines()
        for i, line in enumerate(lines):
            if out_of_line.search(line):
                return path, i
    inline_def = re.compile(rf"~{re.escape(cls)}\s*\([^)]*\)[^;]*\{{")
    for root in ("include/game", "src/game"):
        for path in sorted((REPO_ROOT / root).rglob("*.h")):
            lines = path.read_text(errors="replace").splitlines()
            for i, line in enumerate(lines):
                if inline_def.search(line):
                    return path, i
    return None


def find_class_public_line(cls: str) -> tuple[Path, int, str] | None:
    """(header, 0-based index of the first `public:` inside class `cls`, indent).

    Used by --add-missing for classes whose destructor is implicit: an explicit
    inline ``~C() override {}`` emits the identical COMDAT body the implicit one
    already does, and gives the FUNCTION marker a declaration to sit on
    (destructor-placement gate shape ``inline_proven``).
    """
    class_re = re.compile(rf"^\s*class\s+{re.escape(cls)}\b[^;]*$")
    for root in ("include/game", "src/game"):
        for path in sorted((REPO_ROOT / root).rglob("*.h")):
            text = path.read_text(errors="replace")
            if f"class {cls}" not in text:
                continue
            lines = text.splitlines()
            for i, line in enumerate(lines):
                if not class_re.match(line):
                    continue
                for j in range(i, min(i + 40, len(lines))):
                    stripped = lines[j].strip()
                    if stripped == "public:":
                        indent = lines[j][: len(lines[j]) - len(lines[j].lstrip())] + "  "
                        return path, j, indent
                    if j > i and stripped.startswith("class "):
                        break
                break
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true", help="edit files (default: dry run)")
    ap.add_argument("--limit", type=int, default=0, help="process at most N classes")
    ap.add_argument(
        "--add-missing",
        action="store_true",
        help="for classes with no explicit destructor, insert a marked inline "
        "`~C() override {}` declaration after the class's first `public:`",
    )
    ap.add_argument(
        "--islands",
        action="store_true",
        help="claim fold islands from config/template_aliases.csv "
        "folded_symbol_group rows instead of decoding below-100%% ??_G callers",
    )
    args = ap.parse_args()

    claimed = collect_claimed_addresses()

    candidates: list[tuple[int | None, int, str]]  # (??_G addr or None, target, class)
    if args.islands:
        candidates = [(None, addr, cls) for addr, cls in island_dtor_rows()]
    else:
        pe = Pe(parse_env_binary())
        candidates = []
        for gaddr, _matching, cls in scalar_dtor_rows():
            target = decode_dtor_target(pe, gaddr)
            candidates.append((gaddr, target if target is not None else -1, cls))

    actions: list[tuple[Path, int, int, str, bool]] = []  # file, line-idx, target, class, decl
    report: dict[str, list[str]] = {}
    seen_targets: dict[int, str] = {}

    for gaddr, target, cls in sorted(candidates, key=lambda r: r[1]):
        if args.limit and len(actions) >= args.limit:
            break
        if target < 0:
            report.setdefault("no_call_decoded", []).append(f"{cls} ??_G=0x{gaddr:08x}")
            continue
        if target in claimed:
            report.setdefault("already_claimed", []).append(f"{cls} 0x{target:08x}")
            continue
        if target in seen_targets:
            report.setdefault("duplicate_target", []).append(
                f"{cls} 0x{target:08x} (claimed for {seen_targets[target]})"
            )
            continue
        found = find_definition(cls)
        insert_decl = False
        if found is None:
            if args.add_missing:
                pub = find_class_public_line(cls)
                if pub is None:
                    report.setdefault("no_definition", []).append(f"{cls} dtor=0x{target:08x}")
                    continue
                found = (pub[0], pub[1] + 1)  # insert right after `public:`
                insert_decl = True
            else:
                report.setdefault("no_definition", []).append(f"{cls} dtor=0x{target:08x}")
                continue
        path, idx = found
        lines = path.read_text(errors="replace").splitlines()
        if not insert_decl and idx > 0 and MARKER_RE.search(lines[idx - 1]):
            report.setdefault("marker_conflict", []).append(
                f"{cls} {path.relative_to(REPO_ROOT)}:{idx + 1} already has a marker above"
            )
            continue
        seen_targets[target] = cls
        actions.append((path, idx, target, cls, insert_decl))

    # Apply per file, bottom-up so earlier indices stay valid.
    by_file: dict[Path, list[tuple[int, int, str, bool]]] = {}
    for path, idx, target, cls, insert_decl in actions:
        by_file.setdefault(path, []).append((idx, target, cls, insert_decl))

    for path, edits in sorted(by_file.items()):
        for idx, target, cls, insert_decl in sorted(edits, reverse=True):
            lines = path.read_text(errors="replace").splitlines(keepends=True)
            if insert_decl:
                indent = lines[idx - 1][: len(lines[idx - 1]) - len(lines[idx - 1].lstrip())] + "  "
                new_lines = [
                    f"{indent}// FUNCTION: IMPERIALISM 0x{target:08x}\n",
                    f"{indent}~{cls}() override {{}}\n",
                ]
            else:
                def_line = lines[idx]
                indent = def_line[: len(def_line) - len(def_line.lstrip())]
                new_lines = [f"{indent}// FUNCTION: IMPERIALISM 0x{target:08x}\n"]
            kind = "decl+marker" if insert_decl else "marker"
            print(f"{'APPLY' if args.apply else 'DRY  '} {path.relative_to(REPO_ROOT)}:{idx + 1} "
                  f"{cls} -> 0x{target:08x} [{kind}]")
            if args.apply:
                lines[idx:idx] = new_lines
                path.write_text("".join(lines))

    print(f"\n{len(actions)} marker(s) {'applied' if args.apply else 'planned'} "
          f"across {len(by_file)} file(s)")
    for reason, items in sorted(report.items()):
        print(f"\n[{reason}] {len(items)}")
        for item in items:
            print(f"  {item}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
