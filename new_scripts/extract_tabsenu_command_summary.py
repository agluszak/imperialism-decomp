#!/usr/bin/env python3
"""
Extract command-oriented scenario data from tabsenu TABLE_S* text files.

Outputs:
  - tmp_decomp/tabsenu_scenario_command_counts.csv
  - tmp_decomp/tabsenu_tech_entries.csv
  - tmp_decomp/tabsenu_map_action_entries.csv
  - tmp_decomp/tabsenu_map_action_entries_annotated.csv

Usage:
  .venv/bin/python new_scripts/extract_tabsenu_command_summary.py
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABLE_DIR = ROOT / "Data" / "extracted_tables" / "tabsenu"
OUT_DIR = ROOT / "tmp_decomp"


def scenario_files() -> list[Path]:
    out = []
    for p in sorted(TABLE_DIR.glob("tabsenu.gob_TABLE_S*")):
        # keep base scenario command files only (exclude .INF/.MAP/.SCN)
        if re.match(r"^tabsenu\.gob_TABLE_S\d+$", p.name):
            out.append(p)
    return out


def split_lines(raw: str) -> list[str]:
    # Files are mostly CR-delimited; be robust to CRLF/LF.
    txt = raw.replace("\r\n", "\n").replace("\r", "\n")
    return [ln.strip() for ln in txt.split("\n") if ln.strip()]


def parse_cmd(line: str) -> tuple[str, list[str]] | None:
    # Basic grammar: "<cmd> <arg0> <arg1> ..."
    # Keep quoted/multiword values intact if present.
    m = re.match(r"^([A-Za-z#][A-Za-z0-9#_-]*)\s*(.*)$", line)
    if not m:
        return None
    cmd = m.group(1).lower()
    rest = m.group(2).strip()
    args = rest.split() if rest else []
    return cmd, args


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sfiles = scenario_files()
    if not sfiles:
        print(f"no scenario files in {TABLE_DIR}")
        return 1

    command_rows: list[dict[str, object]] = []
    tech_rows: list[dict[str, object]] = []
    map_rows: list[dict[str, object]] = []
    map_rows_annotated: list[dict[str, object]] = []
    civilian_class_name_by_code = {
        "0": "Miner",
        "1": "Prospector",
        "2": "Farmer",
        "3": "Forester",
        "4": "Engineer",
        "5": "Rancher",
        "7": "Developer",
        "8": "Driller",
    }

    for sf in sfiles:
        scenario = sf.name.replace("tabsenu.gob_TABLE_", "")
        raw = sf.read_text(encoding="latin-1", errors="ignore")
        lines = split_lines(raw)

        counts: Counter[str] = Counter()
        for ln in lines:
            parsed = parse_cmd(ln)
            if parsed is None:
                continue
            cmd, args = parsed
            counts[cmd] += 1

            if cmd == "tech" and len(args) >= 2:
                tech_rows.append(
                    {
                        "scenario": scenario,
                        "nation_index": args[0],
                        "tech_index": args[1],
                        "raw": ln,
                    }
                )

            if cmd in {"civi", "rail", "port", "deve"}:
                arg0 = args[0] if len(args) > 0 else ""
                arg1 = args[1] if len(args) > 1 else ""
                arg2 = args[2] if len(args) > 2 else ""
                row = {
                    "scenario": scenario,
                    "command": cmd,
                    "arg0": arg0,
                    "arg1": arg1,
                    "arg2": arg2,
                    "raw": ln,
                }
                map_rows.append(row)

                map_rows_annotated.append(
                    {
                        **row,
                        "civilian_class_id": arg0 if cmd == "civi" else "",
                        "civilian_class_name": (
                            civilian_class_name_by_code.get(arg0, "")
                            if cmd == "civi"
                            else ""
                        ),
                        "class_mapping_source": (
                            "ghidra:ResolveCivilianTileOrderActionCode/HandleCivilianReportDecision"
                            if cmd == "civi" and arg0 in civilian_class_name_by_code
                            else ""
                        ),
                    }
                )

        for c, n in sorted(counts.items()):
            command_rows.append({"scenario": scenario, "command": c, "count": n})

    counts_csv = OUT_DIR / "tabsenu_scenario_command_counts.csv"
    with counts_csv.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=["scenario", "command", "count"])
        wr.writeheader()
        wr.writerows(command_rows)

    tech_csv = OUT_DIR / "tabsenu_tech_entries.csv"
    with tech_csv.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(
            fh, fieldnames=["scenario", "nation_index", "tech_index", "raw"]
        )
        wr.writeheader()
        wr.writerows(tech_rows)

    map_csv = OUT_DIR / "tabsenu_map_action_entries.csv"
    with map_csv.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(
            fh, fieldnames=["scenario", "command", "arg0", "arg1", "arg2", "raw"]
        )
        wr.writeheader()
        wr.writerows(map_rows)

    map_annotated_csv = OUT_DIR / "tabsenu_map_action_entries_annotated.csv"
    with map_annotated_csv.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(
            fh,
            fieldnames=[
                "scenario",
                "command",
                "arg0",
                "arg1",
                "arg2",
                "civilian_class_id",
                "civilian_class_name",
                "class_mapping_source",
                "raw",
            ],
        )
        wr.writeheader()
        wr.writerows(map_rows_annotated)

    print(f"[saved] {counts_csv} rows={len(command_rows)}")
    print(f"[saved] {tech_csv} rows={len(tech_rows)}")
    print(f"[saved] {map_csv} rows={len(map_rows)}")
    print(f"[saved] {map_annotated_csv} rows={len(map_rows_annotated)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
