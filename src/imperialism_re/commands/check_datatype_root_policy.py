#!/usr/bin/env python3
"""
Check that project-owned datatypes only live under canonical root.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.datatypes import (
    DEFAULT_CANONICAL_PROJECT_ROOT,
    DEFAULT_LEGACY_PROJECT_ROOTS,
    collect_root_policy_violations,
    normalize_root_path,
    parse_roots_csv,
)
from imperialism_re.core.ghidra_session import open_program


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--canonical-root", default=DEFAULT_CANONICAL_PROJECT_ROOT)
    ap.add_argument(
        "--forbidden-roots",
        default=",".join(DEFAULT_LEGACY_PROJECT_ROOTS),
        help="Comma-separated roots that must remain empty for project-owned types",
    )
    ap.add_argument("--out-csv", default="", help="Optional violation CSV output")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    canonical = normalize_root_path(args.canonical_root)
    forbidden = [r for r in parse_roots_csv(args.forbidden_roots) if r != canonical]
    if not forbidden:
        print("[ok] no forbidden roots configured")
        return 0

    with open_program(root) as program:
        dtm = program.getDataTypeManager()
        violations = collect_root_policy_violations(
            dtm, canonical_root=canonical, forbidden_roots=forbidden
        )

    print(
        f"[policy] canonical={canonical} forbidden={','.join(forbidden)} violations={len(violations)}"
    )
    for row in violations[:200]:
        print(f"  {row['full_path']} (root={row['forbidden_root']})")
    if len(violations) > 200:
        print(f"  ... ({len(violations) - 200} more)")

    if args.out_csv:
        out = Path(args.out_csv)
        if not out.is_absolute():
            out = root / out
        write_csv_rows(
            out,
            violations,
            ["full_path", "category_path", "forbidden_root", "canonical_root"],
        )
        print(f"[csv] {out}")

    return 0 if not violations else 2


if __name__ == "__main__":
    raise SystemExit(main())
