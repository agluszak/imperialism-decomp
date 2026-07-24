#!/usr/bin/env python3
"""Enumerate stale-jmp fold islands for config/template_aliases.csv
(folded_symbol_group rows; bd 5jjn.1).

The retail exe is an incremental LINK 5.0 image: a moved/folded symbol's old
address holds only a 5-byte ``jmp rel32`` island (+ nop/int3 padding) whose
chain (through ILT hops) lands on a shared final body owned by another symbol
(ctors-dtors-eh skill, 2026-07-23; e.g. many leaf-view dtors end at TView's
0x48a9d0). Each island IS the folded symbol's canonical address — a
``folded_symbol_group`` alias row maps it to the chain's final body.

Island sources swept here:

1. every sized function row in config/original_entities.csv whose original
   bytes are a bare ``jmp rel32`` (+ padding) outside the ILT band;
2. the first-call target of every ``??_G`` scalar-deleting-destructor row in
   the progress baseline, when that target is such a bare jmp (these islands
   are mostly unclaimed, so source 1 misses them).

Default output is a human report grouped by canonical body; ``--emit`` prints
ready-to-append CSV rows (skipping islands already present in
config/template_aliases.csv).

usage:
  just stale-jmp-islands [--emit]
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

from tools.binary.pe import (
    ILT_HI,
    ILT_LO,
    OriginalImage,
    load_symbol_names,
    load_symbol_sizes,
)
from tools.common.repo import repo_root_from_file
from tools.common.template_aliases import load_alias_rows

REPO_ROOT = repo_root_from_file(__file__)
BASELINE = REPO_ROOT / "config/baselines/reccmp_progress_baseline.functions.csv"
SCALAR_SUFFIX = "::`scalar deleting destructor'"
_PADDING = (0x90, 0xCC)  # nop / int3


def is_bare_jmp_island(img: OriginalImage, addr: int, size: int | None) -> bool:
    """True if [addr, addr+size) is `jmp rel32` followed only by padding."""
    if ILT_LO <= addr < ILT_HI:
        return False  # ILT thunks are trampolines by design, not fold islands
    try:
        body = img.read_va(addr, max(size or 5, 5))
    except ValueError:
        return False
    if len(body) < 5 or body[0] != 0xE9:
        return False
    return all(b in _PADDING for b in body[5 : size or 5])


def first_call_target(img: OriginalImage, gaddr: int) -> int | None:
    """First `call rel32` target within a ??_G body, chased through ILT hops."""
    try:
        body = img.read_va(gaddr, 16)
    except ValueError:
        return None
    idx = body.find(b"\xE8")
    if idx < 0 or idx + 5 > len(body):
        return None
    rel = struct.unpack_from("<i", body, idx + 1)[0]
    return img.resolve_thunk(gaddr + idx + 5 + rel)


def scalar_dtor_rows(path: Path = BASELINE) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    for line in path.read_text().splitlines()[1:]:
        addr_s, _matching, name = line.split("|", 2)
        if name.endswith(SCALAR_SUFFIX):
            rows.append((int(addr_s, 16), name[: -len(SCALAR_SUFFIX)]))
    return rows


def discover_islands(
    img: OriginalImage,
    names: dict[int, str],
    sizes: dict[int, int],
) -> dict[int, tuple[int, str]]:
    """island addr -> (canonical final-body addr, best-available name)."""
    islands: dict[int, tuple[int, str]] = {}

    for addr, size in sorted(sizes.items()):
        if not is_bare_jmp_island(img, addr, size):
            continue
        final = img.resolve_fold_chain(addr)
        if final == addr or final not in sizes:
            continue
        islands[addr] = (final, names.get(addr, ""))

    for gaddr, cls in scalar_dtor_rows():
        target = first_call_target(img, gaddr)
        if target is None or target in islands:
            continue
        if not is_bare_jmp_island(img, target, sizes.get(target)):
            continue
        final = img.resolve_fold_chain(target)
        if final == target or final not in sizes:
            continue
        # The ??_G's first call is the class's ordinary destructor, so the
        # island is that dtor's canonical address; name it accordingly when
        # no curated name exists yet.
        islands[target] = (final, names.get(target, f"{cls}::~{cls}"))

    return islands


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--emit",
        action="store_true",
        help="print CSV rows for islands not yet in config/template_aliases.csv",
    )
    args = ap.parse_args()

    img = OriginalImage()
    names = load_symbol_names()
    sizes = load_symbol_sizes()
    islands = discover_islands(img, names, sizes)

    existing_rows, _errors = load_alias_rows()
    existing = {alias for alias, _c, _n, _cls in existing_rows}
    missing = {a: v for a, v in islands.items() if a not in existing}

    if args.emit:
        for addr in sorted(missing):
            final, name = missing[addr]
            print(f"0x{addr:08x}|0x{final:08x}|{name}|folded_symbol_group")
        print(
            f"# {len(missing)} new row(s); {len(islands) - len(missing)} of "
            f"{len(islands)} island(s) already recorded",
            file=sys.stderr,
        )
        return 0

    by_canonical: dict[int, list[int]] = {}
    for addr, (final, _name) in islands.items():
        by_canonical.setdefault(final, []).append(addr)
    print(f"{len(islands)} stale-jmp island(s) onto {len(by_canonical)} final bodies "
          f"({len(missing)} not yet in template_aliases.csv):\n")
    for final, members in sorted(by_canonical.items(), key=lambda kv: -len(kv[1])):
        print(f"{final:#010x}  {names.get(final, '?')}  <- {len(members)} island(s)")
        for addr in sorted(members):
            _f, name = islands[addr]
            tag = "" if addr in existing else "  [NEW]"
            print(f"    {addr:#010x}  {name or '?'}{tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
