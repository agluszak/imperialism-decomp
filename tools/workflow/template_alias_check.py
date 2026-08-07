#!/usr/bin/env python3
"""Validate config/template_aliases.csv: fold-aware equivalence metadata in four
classes (bd 5jjn), each with its own machine-checkable invariant re-verified on
every run.

duplicate_emission (classification ``per_tu_duplicate``; mfc-collections skill,
MFC-TWIN-030): per-TU copies of the same MFC template instantiation. Evidence:

- addresses parse, alias != canonical, no duplicate alias rows;
- both addresses are sized functions in config/original_entities.csv;
- curated names agree (same instantiation, not merely same shape);
- the normalized instruction structure of alias and canonical is IDENTICAL
  modulo relocations (tools.binary.body_hash), with paired call targets
  recursively equivalent.

folded_symbol_group (ctors-dtors-eh skill, 2026-07-23): incremental-LINK 5.0
fold islands — the alias address holds only a stale ``jmp rel32`` island whose
chain lands on the shared final body. Evidence:

- the alias bytes are a bare ``jmp rel32`` (+ nop/int3 padding, when sized);
- the fold chain (jmp hops through the ILT band and other islands) resolves
  exactly to the canonical address;
- the canonical is a sized function in config/original_entities.csv.

library_callee_alias: a compiler wrapper whose direct call resolves to a linked
library body with the row's canonical decorated identity. The wrapper remains a
distinct report entity; only call operands share the canonical identity.

library_linked_copy: separately linked bodies carrying the same decorated
library symbol. The bodies may differ because each module uses its own state
layout; only their call identity is shared.

Curated names intentionally DIFFER within a folded group (leaf dtor vs shared
base body), so no name check applies there.

Schema (pipe-separated, # comments):
  original_address|canonical_address|decorated_name|classification

Discover duplicate_emission candidates with `just mfc-collection-audit`;
folded_symbol_group candidates with `just stale-jmp-islands`.

usage: just template-alias-check
"""

from __future__ import annotations

from tools.binary.body_hash import bodies_equivalent, normalized_body
from tools.binary.pe import (
    OriginalImage,
    load_decorated_symbols,
    load_symbol_names,
    load_symbol_sizes,
)
from tools.common.template_aliases import (
    ALIASES_CSV,
    CLASS_FOLDED_SYMBOL_GROUP,
    CLASS_LIBRARY_CALLEE_ALIAS,
    CLASS_LIBRARY_LINKED_COPY,
    CLASSIFICATIONS,
    load_alias_rows,
)
from tools.workflow.stale_jmp_islands import is_bare_jmp_island


def _check_duplicate_emission(
    img: OriginalImage,
    names: dict[int, str],
    sizes: dict[int, int],
    alias: int,
    canonical: int,
) -> tuple[bool, str]:
    size_a, size_c = sizes.get(alias), sizes.get(canonical)
    if not size_a or not size_c:
        return False, f"not in symbols.csv (sizes {size_a}/{size_c})"
    # Compatible decorated identity: distinct instantiations over trivially-
    # destructible elements compile to equal shapes, so structural equality
    # alone is not alias evidence -- the curated names must agree too.
    name_a, name_c = names.get(alias), names.get(canonical)
    if name_a and name_c and name_a != name_c:
        return False, f"curated names differ ({name_a} vs {name_c})"
    return bodies_equivalent(img, alias, size_a, canonical, size_c, sizes)


def _check_folded_symbol_group(
    img: OriginalImage,
    sizes: dict[int, int],
    alias: int,
    canonical: int,
) -> tuple[bool, str]:
    if canonical not in sizes:
        return False, f"canonical {canonical:#x} not a sized function in symbols.csv"
    if not is_bare_jmp_island(img, alias, sizes.get(alias)):
        return False, "alias bytes are not a bare `jmp rel32` island"
    final = img.resolve_fold_chain(alias)
    if final != canonical:
        return False, f"fold chain lands on {final:#x}, not the recorded canonical"
    return True, f"jmp island chains to {canonical:#x}"


def _check_library_callee_alias(
    img: OriginalImage,
    symbols: dict[int, str],
    sizes: dict[int, int],
    alias: int,
    canonical: int,
    decorated: str,
) -> tuple[bool, str]:
    alias_size = sizes.get(alias)
    canonical_size = sizes.get(canonical)
    if not alias_size or not canonical_size:
        return False, f"not in symbols.csv (sizes {alias_size}/{canonical_size})"
    if not decorated:
        return False, "missing canonical decorated library identity"

    _, raw_calls = normalized_body(img, alias, alias_size)
    targets = {img.resolve_thunk(target) for target in raw_calls}
    canonical_target = img.resolve_thunk(canonical)
    canonical_symbol = symbols.get(canonical_target)
    matching_symbol_targets = {
        target for target in targets if symbols.get(target) == decorated
    }
    if canonical_symbol != decorated:
        return False, f"canonical symbol is {canonical_symbol!r}, not {decorated!r}"
    if canonical_target not in targets and not matching_symbol_targets:
        rendered = ", ".join(f"{target:#x}" for target in sorted(targets)) or "none"
        return False, f"wrapper direct-call targets are {rendered}"
    reached = canonical_target if canonical_target in targets else min(matching_symbol_targets)
    return True, f"wrapper calls {reached:#x} with canonical identity {decorated}"


def _check_library_linked_copy(
    symbols: dict[int, str],
    sizes: dict[int, int],
    alias: int,
    canonical: int,
    decorated: str,
) -> tuple[bool, str]:
    if not sizes.get(alias) or not sizes.get(canonical):
        return False, f"not in symbols.csv (sizes {sizes.get(alias)}/{sizes.get(canonical)})"
    if not decorated:
        return False, "missing shared decorated library identity"
    alias_symbol = symbols.get(alias)
    canonical_symbol = symbols.get(canonical)
    if alias_symbol != decorated or canonical_symbol != decorated:
        return False, (
            f"linked symbols are {alias_symbol!r}/{canonical_symbol!r}, "
            f"not {decorated!r}"
        )
    return True, f"both linked bodies carry library identity {decorated}"


def main() -> int:
    if not ALIASES_CSV.is_file():
        print(f"no {ALIASES_CSV.name} yet -- nothing to check.")
        return 0
    img = OriginalImage()
    names = load_symbol_names()
    symbols = load_decorated_symbols()
    sizes = load_symbol_sizes()

    rows, errors = load_alias_rows()

    ok = 0
    for alias, canonical, decorated, cls in rows:
        equivalence_class = CLASSIFICATIONS.get(cls)
        if equivalence_class == CLASS_FOLDED_SYMBOL_GROUP:
            equal, reason = _check_folded_symbol_group(img, sizes, alias, canonical)
        elif equivalence_class == CLASS_LIBRARY_CALLEE_ALIAS:
            equal, reason = _check_library_callee_alias(
                img, symbols, sizes, alias, canonical, decorated
            )
        elif equivalence_class == CLASS_LIBRARY_LINKED_COPY:
            equal, reason = _check_library_linked_copy(
                symbols, sizes, alias, canonical, decorated
            )
        else:
            equal, reason = _check_duplicate_emission(img, names, sizes, alias, canonical)
        if not equal:
            errors.append(f"{alias:#x} ({names.get(alias, decorated or '?')}) vs "
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
