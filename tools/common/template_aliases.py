#!/usr/bin/env python3
"""Loader for config/template_aliases.csv: per-TU duplicate MFC-template COMDAT
bodies recorded as aliases of one canonical body (mfc-collections skill, rule
MFC-TWIN-030).

Consumers:
- tools.workflow.template_alias_check re-verifies each row's evidence
  (matching curated names + normalized-body equivalence);
- tools.reccmp.progress_stats reclassifies unpaired alias originals whose
  canonical is paired as "recognized duplicate template bodies" instead of
  unported original-only functions;
- tools.reccmp.core_impact_ranking excludes alias addresses from the porting
  queue (porting the canonical is the work item; an alias never is).
"""

from __future__ import annotations

from pathlib import Path

from tools.common.repo import repo_root_from_file

ALIASES_CSV = repo_root_from_file(__file__) / "config" / "template_aliases.csv"


def load_aliases(path: Path | None = None) -> tuple[dict[int, int], list[str]]:
    """(alias_address -> canonical_address, schema errors). Missing file => empty."""
    csv_path = path or ALIASES_CSV
    aliases: dict[int, int] = {}
    errors: list[str] = []
    if not csv_path.is_file():
        return aliases, errors
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
        if alias in aliases:
            errors.append(f"line {lineno}: duplicate alias row for {alias:#x}")
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
    aliases, errors = load_aliases(csv_path)
    for line in csv_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]  # pipe-split-ok: commented table
        if len(parts) != 4:
            continue
        try:
            alias = int(parts[0], 16)
        except ValueError:
            continue
        if alias in aliases:
            rows.append((alias, aliases[alias], parts[2], parts[3]))
    return rows, errors
