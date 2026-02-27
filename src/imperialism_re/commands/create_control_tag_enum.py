#!/usr/bin/env python3
"""
Create control-tag FourCC enum used in command-tag dispatch handlers.

Creates:
  /imperialism/EControlTagFourCC (size 4)

Tags are stored as the little-endian 4-byte literals observed in code
(e.g. 'txen', 'yako', 'enod').
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import project_category_path
from imperialism_re.core.ghidra_session import open_program


def tag_le_to_u32(tag: str) -> int:
    b = tag.encode("ascii", errors="strict")
    if len(b) != 4:
        raise ValueError(f"tag must be 4 bytes: {tag!r}")
    return int.from_bytes(b, byteorder="little", signed=False)


def load_tags_from_summary_csv(path: Path) -> list[str]:
    tags: list[str] = []
    seen = set()
    with path.open("r", encoding="utf-8", newline="") as fh:
        rd = csv.DictReader(fh)
        for row in rd:
            tag = (row.get("tag_le") or "").strip()
            if len(tag) != 4:
                continue
            if tag in seen:
                continue
            seen.add(tag)
            tags.append(tag)
    return tags


def main() -> int:
    ap = argparse.ArgumentParser()
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--tags",
        default="",
        help="Comma-separated 4-char little-endian tag literals (example: txen,yako,enod)",
    )
    group.add_argument(
        "--tags-summary-csv",
        default="",
        help="Summary CSV path with a tag_le column (for example output of extract_control_tag_usage)",
    )
    ap.add_argument("--enum-name", default="EControlTagFourCC")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()
    root = resolve_project_root(args.project_root)

    if args.tags:
        tags = [t.strip() for t in args.tags.split(",") if t.strip()]
    else:
        summary_csv = Path(args.tags_summary_csv)
        if not summary_csv.is_absolute():
            summary_csv = root / summary_csv
        if not summary_csv.exists():
            print(f"[error] missing tags summary csv: {summary_csv}")
            return 1
        tags = load_tags_from_summary_csv(summary_csv)

    tags = sorted(set(tags))
    bad = [t for t in tags if len(t) != 4]
    if bad:
        print(f"[error] all tags must be 4 chars, got invalid: {','.join(bad)}")
        return 1
    if not tags:
        print("[error] no tags provided")
        return 1

    with open_program(root) as program:
        from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler, EnumDataType

        dtm = program.getDataTypeManager()
        tx = program.startTransaction("Create control tag enum")
        try:
            e = EnumDataType(CategoryPath(project_category_path()), args.enum_name, 4)
            for tag_le in tags:
                member = f"CONTROL_TAG_{tag_le.upper()}"
                e.add(member, tag_le_to_u32(tag_le))
            dt = dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER)
        finally:
            program.endTransaction(tx, True)

        program.save("create control tag enum", None)
        print(f"[done] enum={dt.getPathName()} entries={len(tags)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
