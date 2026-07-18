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
from tools.binary.body_hash import bodies_equivalent
from tools.binary.pe import OriginalImage, load_symbol_names, load_symbol_sizes
from tools.common.template_aliases import ALIASES_CSV, load_alias_rows


def main() -> int:
    if not ALIASES_CSV.is_file():
        print(f"no {ALIASES_CSV.name} yet -- nothing to check.")
        return 0
    img = OriginalImage()
    names = load_symbol_names()
    sizes = load_symbol_sizes()

    rows, errors = load_alias_rows()

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
