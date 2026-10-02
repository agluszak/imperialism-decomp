"""Translate entry addresses through reccmp's entity catalog without decompiling."""

from __future__ import annotations

import argparse
from pathlib import Path

from reccmp.types import ImageId

from tools.common.reccmp_report import load_catalog


def load_entities(target: str, build_dir: Path, queries: list[int]) -> list[dict]:
    catalog = load_catalog(target, build_dir)
    rows = []
    for address in queries:
        entity = catalog.get(ImageId.ORIG, address)
        direction = "orig->recomp"
        if entity is None:
            entity = catalog.get(ImageId.RECOMP, address)
            direction = "recomp->orig"
        rows.append(
            {
                "query": address,
                "direction": direction,
                "orig": entity.orig_addr if entity else None,
                "recomp": entity.recomp_addr if entity else None,
                "name": entity.best_name() if entity else None,
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--build-dir", type=Path, default=Path("build-msvc500"))
    parser.add_argument(
        "addresses", nargs="+", help="original or recompiled hex entry addresses"
    )
    args = parser.parse_args()
    rows = load_entities(
        args.target, args.build_dir, [int(raw, 16) for raw in args.addresses]
    )
    missing = False
    for row in rows:
        orig = hex(row["orig"]) if row["orig"] is not None else "(unpaired)"
        recomp = hex(row["recomp"]) if row["recomp"] is not None else "(unpaired)"
        print(
            f"[{row['direction']}] orig {orig}  recomp {recomp}  {row['name'] or 'unknown'}"
        )
        missing |= row["orig"] is None or row["recomp"] is None
    return int(missing)


if __name__ == "__main__":
    raise SystemExit(main())
