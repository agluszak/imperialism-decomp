#!/usr/bin/env python3
"""Summarize exact archive-oracle identities against the typed reccmp roadmap."""
from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path


def read_rows(path: Path, delimiter: str) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fd:
        return list(csv.DictReader(fd, delimiter=delimiter))


def build_member_rows(
    decisions: list[dict[str, str]], roadmap: list[dict[str, str]]
) -> list[dict[str, str | int]]:
    roadmap_by_orig = {
        int(row["orig_addr"], 16): row
        for row in roadmap
        if row.get("orig_addr")
    }
    recomp_by_member: Counter[str] = Counter()
    for row in roadmap:
        if row.get("pairing_state") != "recomp_only":
            continue
        module = (row.get("module") or "").replace("\\", "/")
        if module:
            recomp_by_member[Path(module).name.lower()] += 1

    counts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for decision in decisions:
        key = (decision.get("library") or "?", decision.get("member") or "?")
        count = counts[key]
        count["oracle_rows"] += 1
        count[decision.get("status") or "oracle-unknown"] += 1
        address = decision.get("address")
        roadmap_row = roadmap_by_orig.get(int(address, 16)) if address else None
        count[
            (roadmap_row or {}).get("pairing_state") or "not_in_roadmap"
        ] += 1

    result: list[dict[str, str | int]] = []
    for (library, member), count in sorted(counts.items()):
        result.append(
            {
                "library": library,
                "member": member,
                "oracle_rows": count["oracle_rows"],
                "already_modeled": count["already-modeled"],
                "selected": count["selected"],
                "paired": count["paired"],
                "original_alias": count["original_alias"],
                "unexplained": count["unexplained"],
                "not_in_roadmap": count["not_in_roadmap"],
                "recomp_only": recomp_by_member[Path(member).name.lower()],
            }
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--decisions",
        default="build-msvc500/evidence/library/reccmp_library_identity_report.csv",
    )
    parser.add_argument("--roadmap", default="build-msvc500/reccmp_roadmap.csv")
    parser.add_argument(
        "--output",
        default="build-msvc500/evidence/library/reccmp_library_member_report.csv",
    )
    args = parser.parse_args()
    rows = build_member_rows(
        read_rows(Path(args.decisions), "|"), read_rows(Path(args.roadmap), ",")
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else ["library", "member"]
    with output.open("w", newline="", encoding="utf-8") as fd:
        writer = csv.DictWriter(fd, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"library member report: {len(rows)} members -> {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
