#!/usr/bin/env python3
"""
Build tabsenu table schema + loader bindings from extracted TABLE_S* scripts.

Outputs:
  - schema CSV (command arity/domain hints)
  - loader binding CSV (command -> handler mapping via scenario token table)
  - JSON summary
  - optional rename/comment CSV for apply_function_renames_csv.py

Usage:
  .venv/bin/python new_scripts/build_tabsenu_schema_loader_bindings.py \
    --out-prefix tmp_decomp/batch371_tabsenu
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


def split_lines(raw: str) -> list[str]:
    txt = raw.replace("\r\n", "\n").replace("\r", "\n")
    return [ln.strip() for ln in txt.split("\n") if ln.strip()]


def parse_cmd(line: str) -> tuple[str, list[str]] | None:
    m = re.match(r"^([A-Za-z#][A-Za-z0-9#_-]*)\s*(.*)$", line)
    if not m:
        return None
    cmd = m.group(1).lower()
    rest = m.group(2).strip()
    args = rest.split() if rest else []
    return cmd, args


def read_token_binding_map(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    rows = list(csv.DictReader(path.open("r", encoding="utf-8", newline="")))
    out: dict[str, dict[str, str]] = {}
    for r in rows:
        token = (r.get("token_decoded") or r.get("token") or "").strip().lower()
        if not token:
            continue
        out[token] = {
            "token_raw": (r.get("token_raw") or "").strip(),
            "stub_va": (r.get("stub_va") or r.get("stub_addr") or "").strip(),
            "stub_name": (r.get("stub_name") or "").strip(),
            "target_va": (r.get("target_va") or r.get("target_addr") or "").strip(),
            "target_name": (r.get("target_name") or "").strip(),
            "index": (r.get("index") or "").strip(),
        }
    return out


def arg_domain_hint(args: list[str]) -> str:
    if not args:
        return "none"
    if all(a.isdigit() for a in args):
        return "numeric"
    if any(a.isdigit() for a in args):
        return "mixed"
    return "symbolic"


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--tables-root",
        default="Data/extracted_tables/tabsenu",
        help="Path containing extracted tabsenu table files",
    )
    ap.add_argument(
        "--token-map-csv",
        default="tmp_decomp/scenario_dispatch_token_handler_map_batch55.csv",
        help="Scenario token map CSV (batch55 preferred)",
    )
    ap.add_argument(
        "--out-prefix",
        default="tmp_decomp/batch371_tabsenu",
        help="Output prefix, e.g. tmp_decomp/batch371_tabsenu",
    )
    ap.add_argument(
        "--strict-arity-overrides",
        default="cnam:2,pnam:2,zone:2",
        help=(
            "Comma-separated strict arity overrides, e.g. "
            "'cnam:2,pnam:2,zone:2' for mixed-arity text-tail commands"
        ),
    )
    return ap.parse_args()


def parse_strict_arity_overrides(raw: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for part in (raw or "").split(","):
        token = part.strip()
        if not token:
            continue
        if ":" not in token:
            continue
        cmd, arity_txt = token.split(":", 1)
        cmd = cmd.strip().lower()
        arity_txt = arity_txt.strip()
        if not cmd:
            continue
        try:
            arity = int(arity_txt)
        except Exception:
            continue
        if arity < 0:
            continue
        out[cmd] = arity
    return out


def main() -> int:
    args = parse_args()
    root = Path(args.tables_root).resolve()
    token_map_csv = Path(args.token_map_csv).resolve()
    out_prefix = Path(args.out_prefix).resolve()
    strict_arity_overrides = parse_strict_arity_overrides(args.strict_arity_overrides)
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    if not root.exists():
        print(f"[error] tables root not found: {root}")
        return 1

    s_files = sorted(
        p for p in root.glob("tabsenu.gob_TABLE_S*") if re.fullmatch(r"tabsenu\.gob_TABLE_S\d+", p.name)
    )
    if not s_files:
        print(f"[error] no TABLE_S* files found under {root}")
        return 1

    command_rows: list[dict[str, str]] = []
    by_cmd: dict[str, dict[str, object]] = defaultdict(
        lambda: {
            "count": 0,
            "arity_counter_loose": Counter(),
            "arity_counter_strict": Counter(),
            "scenarios": set(),
            "examples": [],
            "arg_domain_counter": Counter(),
        }
    )
    by_scenario_cmd_count: dict[str, Counter[str]] = defaultdict(Counter)

    for sf in s_files:
        scenario = sf.name.replace("tabsenu.gob_TABLE_", "")
        raw = sf.read_text(encoding="latin-1", errors="ignore")
        for ln in split_lines(raw):
            parsed = parse_cmd(ln)
            if parsed is None:
                continue
            cmd, argv = parsed
            row = {
                "scenario": scenario,
                "command": cmd,
                "arity_loose": str(len(argv)),
                "arity_strict": str(strict_arity_overrides.get(cmd, len(argv))),
                "arg_domain": arg_domain_hint(argv),
                "raw": ln,
            }
            command_rows.append(row)

            agg = by_cmd[cmd]
            agg["count"] += 1
            agg["arity_counter_loose"][len(argv)] += 1
            agg["arity_counter_strict"][strict_arity_overrides.get(cmd, len(argv))] += 1
            agg["scenarios"].add(scenario)
            agg["arg_domain_counter"][row["arg_domain"]] += 1
            if len(agg["examples"]) < 4:
                agg["examples"].append(ln)
            by_scenario_cmd_count[scenario][cmd] += 1

    token_map = read_token_binding_map(token_map_csv)

    schema_rows: list[dict[str, str]] = []
    binding_rows: list[dict[str, str]] = []
    apply_rows: list[dict[str, str]] = []

    for cmd in sorted(by_cmd.keys()):
        agg = by_cmd[cmd]
        arity_counter_loose: Counter[int] = agg["arity_counter_loose"]  # type: ignore[assignment]
        arities_loose = sorted(arity_counter_loose.keys())
        primary_arity_loose = arity_counter_loose.most_common(1)[0][0]
        record_size_guess_loose = 4 + (primary_arity_loose * 4)
        arity_counter_strict: Counter[int] = agg["arity_counter_strict"]  # type: ignore[assignment]
        arities_strict = sorted(arity_counter_strict.keys())
        primary_arity_strict = arity_counter_strict.most_common(1)[0][0]
        record_size_guess_strict = 4 + (primary_arity_strict * 4)
        arg_domain = agg["arg_domain_counter"].most_common(1)[0][0]  # type: ignore[index]

        binding = token_map.get(cmd, {})
        is_bound = bool(binding.get("target_va") and binding.get("target_name"))

        schema_rows.append(
            {
                "command": cmd,
                "hits": str(agg["count"]),
                "arity_min_loose": str(min(arities_loose)),
                "arity_max_loose": str(max(arities_loose)),
                "arity_primary_loose": str(primary_arity_loose),
                "record_size_guess_loose": str(record_size_guess_loose),
                "arity_min_strict": str(min(arities_strict)),
                "arity_max_strict": str(max(arities_strict)),
                "arity_primary_strict": str(primary_arity_strict),
                "record_size_guess_strict": str(record_size_guess_strict),
                "strict_arity_override": str(strict_arity_overrides.get(cmd, "")),
                "arg_domain_primary": str(arg_domain),
                "scenario_count": str(len(agg["scenarios"])),
                "scenarios": ";".join(sorted(agg["scenarios"])),
                "is_loader_bound": "1" if is_bound else "0",
                "example_1": agg["examples"][0] if agg["examples"] else "",
                "example_2": agg["examples"][1] if len(agg["examples"]) > 1 else "",
            }
        )

        binding_rows.append(
            {
                "command": cmd,
                "token_raw": binding.get("token_raw", ""),
                "dispatch_index": binding.get("index", ""),
                "stub_va": binding.get("stub_va", ""),
                "stub_name": binding.get("stub_name", ""),
                "target_va": binding.get("target_va", ""),
                "target_name": binding.get("target_name", ""),
                "arity_primary_loose": str(primary_arity_loose),
                "record_size_guess_loose": str(record_size_guess_loose),
                "arity_primary_strict": str(primary_arity_strict),
                "record_size_guess_strict": str(record_size_guess_strict),
                "strict_arity_override": str(strict_arity_overrides.get(cmd, "")),
                "is_bound": "1" if is_bound else "0",
            }
        )

        if is_bound:
            target_va = binding.get("target_va", "")
            target_name = binding.get("target_name", "")
            if target_va and target_name:
                apply_rows.append(
                    {
                        "address": target_va,
                        "new_name": target_name,
                        "comment": (
                            f"[TabsenuLoader] command={cmd} dispatch_index={binding.get('index','?')} "
                            f"primary_arity_loose={primary_arity_loose} "
                            f"record_size_guess_loose={record_size_guess_loose} "
                            f"primary_arity_strict={primary_arity_strict} "
                            f"record_size_guess_strict={record_size_guess_strict} "
                            f"source=Data/extracted_tables/tabsenu/TABLE_S*"
                        ),
                    }
                )

    schema_csv = Path(str(out_prefix) + "_command_schema.csv")
    binding_csv = Path(str(out_prefix) + "_loader_bindings.csv")
    apply_csv = Path(str(out_prefix) + "_loader_comment_apply.csv")
    commands_csv = Path(str(out_prefix) + "_command_rows.csv")
    summary_json = Path(str(out_prefix) + "_summary.json")

    with schema_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "command",
                "hits",
                "arity_min_loose",
                "arity_max_loose",
                "arity_primary_loose",
                "record_size_guess_loose",
                "arity_min_strict",
                "arity_max_strict",
                "arity_primary_strict",
                "record_size_guess_strict",
                "strict_arity_override",
                "arg_domain_primary",
                "scenario_count",
                "scenarios",
                "is_loader_bound",
                "example_1",
                "example_2",
            ],
        )
        w.writeheader()
        w.writerows(schema_rows)

    with binding_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "command",
                "token_raw",
                "dispatch_index",
                "stub_va",
                "stub_name",
                "target_va",
                "target_name",
                "arity_primary_loose",
                "record_size_guess_loose",
                "arity_primary_strict",
                "record_size_guess_strict",
                "strict_arity_override",
                "is_bound",
            ],
        )
        w.writeheader()
        w.writerows(binding_rows)

    with apply_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["address", "new_name", "comment"])
        w.writeheader()
        w.writerows(apply_rows)

    with commands_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["scenario", "command", "arity_loose", "arity_strict", "arg_domain", "raw"],
        )
        w.writeheader()
        w.writerows(command_rows)

    by_scenario = {
        scen: dict(sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0])))
        for scen, cnt in sorted(by_scenario_cmd_count.items())
    }
    bound = sum(1 for r in binding_rows if r["is_bound"] == "1")
    summary = {
        "tables_root": str(root),
        "token_map_csv": str(token_map_csv),
        "scenario_files": [p.name for p in s_files],
        "scenario_count": len(s_files),
        "commands_total_rows": len(command_rows),
        "unique_commands": len(schema_rows),
        "strict_arity_overrides": strict_arity_overrides,
        "loader_bound_commands": bound,
        "loader_unbound_commands": len(schema_rows) - bound,
        "scenario_command_counts": by_scenario,
        "outputs": {
            "command_schema_csv": str(schema_csv),
            "loader_bindings_csv": str(binding_csv),
            "loader_comment_apply_csv": str(apply_csv),
            "command_rows_csv": str(commands_csv),
            "summary_json": str(summary_json),
        },
    }
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"[saved] {schema_csv} rows={len(schema_rows)}")
    print(f"[saved] {binding_csv} rows={len(binding_rows)}")
    print(f"[saved] {apply_csv} rows={len(apply_rows)}")
    print(f"[saved] {commands_csv} rows={len(command_rows)}")
    print(f"[saved] {summary_json}")
    print(f"[stats] unique_commands={len(schema_rows)} bound={bound} unbound={len(schema_rows)-bound}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
