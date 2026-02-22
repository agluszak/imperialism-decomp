#!/usr/bin/env python3
"""Generate the next decomp session loop from current reccmp artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ANNOT_RE_TEMPLATE = r"//\s*(FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY)\s*:\s*{target}\s+(?:0x)?([0-9a-fA-F]+)"


@dataclass(frozen=True)
class Location:
    path: Path
    line: int
    kind: str


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--build-dir", default=str(repo_root / "build-msvc500"))
    parser.add_argument("--top", type=int, default=50, help="Ranking depth.")
    parser.add_argument("--pick", type=int, default=8, help="How many targets to queue.")
    parser.add_argument("--min-size", type=int, default=1)
    parser.add_argument(
        "--no-refresh-ignore",
        action="store_true",
        help="Skip ignore regeneration/apply.",
    )
    parser.add_argument(
        "--run-reccmp",
        action="store_true",
        help="Run reccmp before stats (default: parse existing files only).",
    )
    parser.add_argument(
        "--output-md",
        default=str(repo_root / "build-msvc500" / "next_loop.md"),
        help="Markdown output path.",
    )
    parser.add_argument(
        "--output-json",
        default=str(repo_root / "build-msvc500" / "next_loop.json"),
        help="JSON output path.",
    )
    return parser.parse_args()


def run_cmd(cmd: list[str], cwd: Path) -> None:
    proc = subprocess.run(cmd, cwd=cwd, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd)}")


def load_last_history_entry(path: Path) -> dict | None:
    if not path.is_file():
        return None
    last = None
    with path.open("r", encoding="utf-8") as fd:
        for line in fd:
            line = line.strip()
            if line:
                last = json.loads(line)
    return last


def load_core_ranked(path: Path) -> list[dict]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return list(raw.get("ranked") or [])


def build_annotation_index(src_root: Path, target: str) -> dict[int, list[Location]]:
    rx = re.compile(ANNOT_RE_TEMPLATE.format(target=re.escape(target)))
    out: dict[int, list[Location]] = {}
    for cpp in src_root.rglob("*.cpp"):
        try:
            text = cpp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            m = rx.search(line)
            if not m:
                continue
            kind = m.group(1).upper()
            addr = int(m.group(2), 16)
            out.setdefault(addr, []).append(Location(path=cpp, line=i, kind=kind))
    return out


def pick_best_location(locations: list[Location]) -> Location:
    def weight(loc: Location) -> tuple[int, int, str]:
        path_s = str(loc.path).replace("\\", "/")
        if "/src/game/" in path_s:
            bucket = 0
        elif "/src/ghidra_autogen/" in path_s:
            bucket = 1
        elif "/src/autogen/stubs/" in path_s:
            bucket = 2
        else:
            bucket = 3
        return (bucket, 0 if loc.kind == "FUNCTION" else 1, path_s)

    return sorted(locations, key=weight)[0]


def load_ghidra_index(path: Path) -> dict[int, str]:
    if not path.is_file():
        return {}
    out: dict[int, str] = {}
    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        for row in reader:
            addr_raw = (row.get("address") or "").strip()
            file_raw = (row.get("file") or "").strip()
            if not addr_raw:
                continue
            try:
                addr = int(addr_raw, 16)
            except ValueError:
                continue
            out[addr] = file_raw
    return out


def action_hint(path: str, ghidra_file: str | None) -> str:
    normalized = path.replace("\\", "/")
    if "/src/autogen/stubs/" in normalized:
        if ghidra_file:
            return f"Promote from stub into manual source using body in src/ghidra_autogen/{ghidra_file}."
        return "Promote from stub into manual source file."
    if "/src/ghidra_autogen/" in normalized:
        return "Move/rewrite into manual source and keep ghidra_autogen as reference."
    return "Refine implementation for higher similarity."


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    build_dir = Path(args.build_dir).resolve()
    build_dir.mkdir(parents=True, exist_ok=True)

    if not args.no_refresh_ignore:
        run_cmd(
            [
                sys.executable,
                str(repo_root / "tools" / "reccmp" / "generate_ignore_functions.py"),
                "--target",
                args.target,
                "--apply",
            ],
            cwd=repo_root,
        )

    stats_cmd = [
        sys.executable,
        str(repo_root / "tools" / "reccmp" / "progress_stats.py"),
        "--target",
        args.target,
        "--build-dir",
        str(build_dir),
    ]
    if not args.run_reccmp:
        stats_cmd.append("--no-run")
    run_cmd(stats_cmd, cwd=repo_root)

    core_json = build_dir / "core_impact.json"
    core_csv = build_dir / "core_impact.csv"
    run_cmd(
        [
            sys.executable,
            str(repo_root / "tools" / "reccmp" / "core_impact_ranking.py"),
            "--target",
            args.target,
            "--top",
            str(args.top),
            "--min-size",
            str(args.min_size),
            "--json-out",
            str(core_json),
            "--csv-out",
            str(core_csv),
        ],
        cwd=repo_root,
    )

    history = load_last_history_entry(build_dir / "reccmp_progress_history.jsonl") or {}
    ranked = load_core_ranked(core_json)
    annot_index = build_annotation_index(repo_root / "src", args.target)
    ghidra_index = load_ghidra_index(repo_root / "src" / "ghidra_autogen" / "index.csv")

    selected: list[dict] = []
    for row in ranked:
        if len(selected) >= args.pick:
            break
        if float(row.get("similarity_pct") or 0.0) >= 100.0:
            continue
        addr = int(row["address"])
        locs = annot_index.get(addr, [])
        loc = pick_best_location(locs) if locs else None
        ghidra_file = ghidra_index.get(addr)
        source_path = str(loc.path.relative_to(repo_root)) if loc else ""
        source_line = int(loc.line) if loc else 0
        source_kind = loc.kind if loc else ""
        selected.append(
            {
                **row,
                "address_hex": f"0x{addr:08x}",
                "source_path": source_path,
                "source_line": source_line,
                "source_kind": source_kind,
                "ghidra_file": ghidra_file,
                "action_hint": action_hint(source_path, ghidra_file),
            }
        )

    now = datetime.now(timezone.utc).isoformat()
    out_md = Path(args.output_md)
    out_json = Path(args.output_json)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    md_lines: list[str] = []
    md_lines.append(f"# Next Session Loop ({args.target})")
    md_lines.append("")
    md_lines.append(f"- Generated: {now}")
    if history:
        md_lines.append(f"- Aligned: {history.get('aligned_fun_count', 'n/a')}")
        md_lines.append(
            f"- Avg similarity: {float(history.get('avg_matching_pct', 0.0)):.2f}%"
        )
        md_lines.append(f"- Compared: {history.get('compared_fun_count', 'n/a')}")
    md_lines.append("")
    md_lines.append("## Queue (by impact)")
    md_lines.append("")
    md_lines.append("| # | Address | Size | Sim % | Impact | Name | Source |")
    md_lines.append("|---|---|---:|---:|---:|---|---|")
    for i, row in enumerate(selected, start=1):
        src = row["source_path"]
        if row["source_line"]:
            src = f"{src}:{row['source_line']}"
        md_lines.append(
            "| {idx} | {addr} | {size} | {sim:.2f} | {impact:.2f} | {name} | `{src}` |".format(
                idx=i,
                addr=row["address_hex"],
                size=int(row.get("size") or 0),
                sim=float(row.get("similarity_pct") or 0.0),
                impact=float(row.get("impact") or 0.0),
                name=row.get("name") or "",
                src=src or "(unmapped)",
            )
        )
    md_lines.append("")
    md_lines.append("## Actions")
    md_lines.append("")
    for i, row in enumerate(selected, start=1):
        md_lines.append(
            f"{i}. `{row['address_hex']}` `{row['name']}`: {row['action_hint']}"
        )
    md_lines.append("")
    md_lines.append("## Commands")
    md_lines.append("")
    md_lines.append(
        "1. `uv run python tools/reccmp/session_loop.py --target IMPERIALISM --pick 8 --top 50 --min-size 1`"
    )
    md_lines.append(
        "2. `uv run python tools/reccmp/progress_stats.py --target IMPERIALISM --build-dir build-msvc500 --no-run`"
    )
    md_lines.append(
        "3. `uv run python tools/reccmp/core_impact_ranking.py --target IMPERIALISM --top 50 --min-size 1`"
    )
    out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    payload = {
        "generated_utc": now,
        "target": args.target,
        "history": history,
        "queue": selected,
        "artifacts": {
            "core_impact_json": str(core_json),
            "core_impact_csv": str(core_csv),
            "queue_markdown": str(out_md),
        },
    }
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    print(f"Wrote: {out_md}")
    print(f"Wrote: {out_json}")
    print("")
    print("Top queued targets:")
    for row in selected:
        src = row["source_path"] or "(unmapped)"
        if row["source_line"]:
            src = f"{src}:{row['source_line']}"
        print(
            "- {addr}  size={size} sim={sim:.2f}% impact={impact:.2f}  {name}  [{src}]".format(
                addr=row["address_hex"],
                size=int(row.get("size") or 0),
                sim=float(row.get("similarity_pct") or 0.0),
                impact=float(row.get("impact") or 0.0),
                name=row.get("name") or "",
                src=src,
            )
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
