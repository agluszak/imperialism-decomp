#!/usr/bin/env python3
"""Load comparison aliases used by stub generation and reccmp.

Each row maps a known duplicate, folded symbol, or library copy to the
canonical body that comparison should use.  The table is evidence, not a
source-model or migration layer.
"""

from __future__ import annotations

from pathlib import Path

from tools.common.repo import repo_root_from_file

ALIASES_CSV = repo_root_from_file(__file__) / "config" / "template_aliases.csv"

CLASS_DUPLICATE_EMISSION = "duplicate_emission"
CLASS_FOLDED_SYMBOL_GROUP = "folded_symbol_group"
CLASS_LIBRARY_CALLEE_ALIAS = "library_callee_alias"
CLASS_LIBRARY_LINKED_COPY = "library_linked_copy"

# classification column value -> equivalence class
CLASSIFICATIONS: dict[str, str] = {
    "per_tu_duplicate": CLASS_DUPLICATE_EMISSION,
    "folded_symbol_group": CLASS_FOLDED_SYMBOL_GROUP,
    "library_callee_alias": CLASS_LIBRARY_CALLEE_ALIAS,
    "library_linked_copy": CLASS_LIBRARY_LINKED_COPY,
}


def load_aliases(
    path: Path | None = None, equivalence_class: str | None = None
) -> tuple[dict[int, int], list[str]]:
    """Return alias-to-canonical mappings and validation errors.

    ``equivalence_class`` restricts the mapping to rows of that class; None
    returns every row.
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
        # cannot skip; validate its four fields here.
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
