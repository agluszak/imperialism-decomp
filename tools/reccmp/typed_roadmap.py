#!/usr/bin/env python3
"""Run reccmp-roadmap with the Imperialism typed CSV schema.

Upstream's presentation CSV truncates EntityType names to three characters.
That makes IMPORT and IMPORT_THUNK indistinguishable, so machine consumers use
this wrapper instead.  Text output remains otherwise identical.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

from reccmp.tools import roadmap
from reccmp.types import EntityType


def typed_entity_name(entity_type: int | None) -> str:
    return "" if entity_type is None else EntityType(entity_type).name.lower()


def pairing_state(row: roadmap.RoadmapRow) -> str:
    if row.orig_addr is not None and row.recomp_addr is not None:
        return "paired"
    if row.orig_addr is not None:
        return "unexplained"
    return "recomp_only"


def export_typed_csv(csv_file: str, results: Iterable[roadmap.RoadmapRow]) -> None:
    fields = [
        "orig_sect_ofs", "recomp_sect_ofs", "orig_addr", "recomp_addr",
        "displacement", "row_type", "pairing_state", "size", "name", "module",
    ]
    with Path(csv_file).open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(fd, fieldnames=fields)
        writer.writeheader()
        for row in results:
            writer.writerow({
                "orig_sect_ofs": roadmap.or_blank(row.orig_sect_ofs),
                "recomp_sect_ofs": roadmap.or_blank(row.recomp_sect_ofs),
                "orig_addr": roadmap.or_blank(row.orig_addr),
                "recomp_addr": roadmap.or_blank(row.recomp_addr),
                "displacement": roadmap.or_blank(row.displacement),
                "row_type": row.sym_type,
                "pairing_state": pairing_state(row),
                "size": roadmap.or_blank(row.size),
                "name": roadmap.or_blank(row.name),
                "module": roadmap.or_blank(row.module),
            })


def main() -> int:
    roadmap.match_type_abbreviation = typed_entity_name
    roadmap.export_to_csv = export_typed_csv
    return roadmap.main()


if __name__ == "__main__":
    raise SystemExit(main())
