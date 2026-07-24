#!/usr/bin/env python3
"""Loader for config/template_aliases.csv: fold-aware equivalence metadata.

Two distinct equivalence classes share the table (bd 5jjn):

- duplicate_emission (classification ``per_tu_duplicate``): per-TU duplicate
  MFC-template COMDAT bodies recorded as aliases of one canonical body
  (mfc-collections skill, rule MFC-TWIN-030). Many original ADDRESSES carry the
  same instantiation; the recomp legitimately emits one copy. Evidence:
  matching curated names + normalized-body equivalence (tools.binary.body_hash).

- folded_symbol_group (classification ``folded_symbol_group``): incremental-
  LINK 5.0 fold/alias islands (ctors-dtors-eh skill, 2026-07-23). The original
  SYMBOL's canonical address holds only a stale 5-byte ``jmp`` island whose
  chain (through ILT hops) lands on one shared final body owned by another
  symbol (e.g. many leaf-view dtors end at TView's 0x48a9d0). Evidence: the
  alias bytes are a bare ``jmp rel32`` (+ nop/int3 padding) and the chain
  resolves exactly to the canonical address.

Consumers:
- tools.workflow.template_alias_check re-verifies each row's per-class
  evidence;
- tools.reccmp.progress_stats reclassifies unpaired duplicate_emission
  originals whose canonical is paired as "recognized duplicate template
  bodies" instead of unported original-only functions;
- tools.reccmp.core_impact_ranking excludes alias addresses of both classes
  from the porting queue (porting/claiming the canonical is the work item; an
  alias body never is).
"""

from __future__ import annotations

from pathlib import Path

from tools.common.repo import repo_root_from_file

ALIASES_CSV = repo_root_from_file(__file__) / "config" / "template_aliases.csv"

CLASS_DUPLICATE_EMISSION = "duplicate_emission"
CLASS_FOLDED_SYMBOL_GROUP = "folded_symbol_group"

# classification column value -> equivalence class
CLASSIFICATIONS: dict[str, str] = {
    "per_tu_duplicate": CLASS_DUPLICATE_EMISSION,
    "folded_symbol_group": CLASS_FOLDED_SYMBOL_GROUP,
}


def load_aliases(
    path: Path | None = None, equivalence_class: str | None = None
) -> tuple[dict[int, int], list[str]]:
    """(alias_address -> canonical_address, schema errors). Missing file => empty.

    ``equivalence_class`` (CLASS_DUPLICATE_EMISSION / CLASS_FOLDED_SYMBOL_GROUP)
    restricts the mapping to rows of that class; None returns every row.
    """
    rows, errors = load_alias_rows(path)
    aliases: dict[int, int] = {}
    for alias, canonical, _decorated, cls in rows:
        if equivalence_class is not None and CLASSIFICATIONS.get(cls) != equivalence_class:
            continue
        aliases[alias] = canonical
    return aliases, errors


def load_alias_rows(
    path: Path | None = None,
) -> tuple[list[tuple[int, int, str, str]], list[str]]:
    """Full rows (alias, canonical, decorated_name, classification) + errors."""
    csv_path = path or ALIASES_CSV
    rows: list[tuple[int, int, str, str]] = []
    errors: list[str] = []
    if not csv_path.is_file():
        return rows, errors
    seen: set[int] = set()
    for lineno, line in enumerate(csv_path.read_text(encoding="utf-8").splitlines(), 1):
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
        if alias in seen:
            errors.append(f"line {lineno}: duplicate alias row for {alias:#x}")
            continue
        if parts[3] not in CLASSIFICATIONS:
            errors.append(
                f"line {lineno}: unknown classification {parts[3]!r} "
                f"(expected one of {sorted(CLASSIFICATIONS)})"
            )
            continue
        seen.add(alias)
        rows.append((alias, canonical, parts[2], parts[3]))
    return rows, errors
