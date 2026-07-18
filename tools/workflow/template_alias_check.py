#!/usr/bin/env python3
"""Validate config/template_aliases.csv: duplicate original template COMDAT
bodies recorded as aliases of one canonical body.

Per the mfc-collections skill (MFC-TWIN-030): the original executable emits
per-TU copies of the same MFC template instantiation. Those copies are aliases
in comparison metadata, never additional game classes or duplicate source
instantiations. Every alias row must carry machine-checkable evidence, which
this tool re-verifies on each run:

- addresses parse, alias != canonical, no duplicate alias rows;
- both addresses are known functions in config/symbols.csv;
- the normalized instruction structure of alias and canonical is IDENTICAL
  modulo relocations (tools.binary.body_hash) -- same layout, same shape,
  differing only in call targets / EH refs / data addresses.

Schema (pipe-separated, # comments):
  original_address|canonical_address|decorated_name|classification

usage: just template-alias-check
"""

from __future__ import annotations

import sys
from pathlib import Path

from tools.binary.body_hash import bodies_equivalent
from tools.binary.pe import OriginalImage, load_symbol_names, load_symbol_sizes

REPO_ROOT = Path(__file__).resolve().parents[2]
ALIASES_CSV = REPO_ROOT / "config" / "template_aliases.csv"


def main() -> int:
    if not ALIASES_CSV.is_file():
        print(f"no {ALIASES_CSV.relative_to(REPO_ROOT)} yet -- nothing to check.")
        return 0
    img = OriginalImage()
    names = load_symbol_names()
    sizes = load_symbol_sizes()

    rows: list[tuple[int, int, str, str]] = []
    errors: list[str] = []
    seen_alias: set[int] = set()
    for lineno, line in enumerate(ALIASES_CSV.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # The file carries '#' comment lines, which csv.DictReader (pipe_csv)
        # cannot skip; the 4-field schema is validated immediately below.
        parts = [p.strip() for p in line.split("|")]  # pipe-split-ok: commented table
        if len(parts) != 4:
            errors.append(f"line {lineno}: expected 4 pipe-separated fields")
            continue
        try:
            alias = int(parts[0], 16)
            canonical = int(parts[1], 16)
        except ValueError:
            errors.append(f"line {lineno}: unparsable address")
            continue
        if alias == canonical:
            errors.append(f"line {lineno}: alias equals canonical ({alias:#x})")
            continue
        if alias in seen_alias:
            errors.append(f"line {lineno}: duplicate alias row for {alias:#x}")
            continue
        seen_alias.add(alias)
        rows.append((alias, canonical, parts[2], parts[3]))

    ok = 0
    for alias, canonical, decorated, cls in rows:
        size_a, size_c = sizes.get(alias), sizes.get(canonical)
        if not size_a or not size_c:
            errors.append(f"{alias:#x} -> {canonical:#x}: not in symbols.csv "
                          f"(sizes {size_a}/{size_c})")
            continue
        # Compatible decorated identity: distinct instantiations over trivially-
        # destructible elements compile to equal shapes, so structural equality
        # alone is not alias evidence -- the curated names must agree too.
        name_a, name_c = names.get(alias), names.get(canonical)
        if name_a and name_c and name_a != name_c:
            errors.append(f"{alias:#x} ({name_a}) vs {canonical:#x} ({name_c}): "
                          f"curated names differ -- not the same instantiation")
            continue
        equal, reason = bodies_equivalent(img, alias, size_a, canonical, size_c, sizes)
        if not equal:
            errors.append(f"{alias:#x} ({names.get(alias, '?')}) vs "
                          f"{canonical:#x} ({names.get(canonical, '?')}): {reason}")
            continue
        ok += 1
        print(f"OK  {alias:#010x} -> {canonical:#010x}  [{cls}]  {reason}")

    if errors:
        print(f"\nTemplate-alias check FAILED ({len(errors)} error(s)):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"Template-alias check passed ({ok} alias(es) verified).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
