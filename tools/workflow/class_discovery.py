#!/usr/bin/env python3
"""Run read-only class/vtable discovery against imperialism_knowledge via impk."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.workflow.function_ownership import (
    DEFAULT_FUNCTION_OWNERSHIP_CSV,
    load_function_ownership,
)

CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
RANK_TO_CONFIDENCE = {v: k for k, v in CONFIDENCE_RANK.items()}


def normalize_hex(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if not raw.startswith("0x"):
        raw = f"0x{raw}"
    try:
        return f"0x{int(raw, 16):08x}"
    except ValueError:
        return ""


def split_csv_values(value: str) -> list[str]:
    raw = (value or "").strip()
    if not raw:
        return []
    return [chunk for chunk in (part.strip() for part in raw.split("|")) if chunk]


def parse_classes(raw: str) -> list[str]:
    classes = [item.strip() for item in raw.split(",") if item.strip()]
    if not classes:
        raise SystemExit("No classes were provided.")
    return classes


def class_slug(classes: list[str]) -> str:
    normalized: list[str] = []
    for cls in classes:
        cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", cls).strip("_").lower()
        normalized.append(cleaned or "class")
    return "_".join(normalized)


def run_command(cmd: list[str], cwd: Path, *, capture_output: bool = False) -> str:
    print("[run]", " ".join(cmd))
    env = dict(os.environ)
    # Avoid noisy uv warnings when the caller's active venv differs from --project.
    env.pop("VIRTUAL_ENV", None)
    cp = subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    if cp.returncode != 0:
        if cp.stdout:
            print(cp.stdout.rstrip())
        if cp.stderr:
            print(cp.stderr.rstrip(), file=sys.stderr)
        raise RuntimeError(f"Command failed ({cp.returncode}): {' '.join(cmd)}")
    if capture_output:
        return cp.stdout
    if cp.stdout:
        print(cp.stdout.rstrip())
    if cp.stderr:
        print(cp.stderr.rstrip(), file=sys.stderr)
    return ""


def run_impk(
    knowledge_root: Path,
    impk_args: list[str],
    *,
    capture_output: bool = False,
) -> str:
    cmd = [
        "uv",
        "run",
        "--project",
        str(knowledge_root),
        "impk",
        *impk_args,
    ]
    return run_command(cmd, knowledge_root, capture_output=capture_output)


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as fd:
        return list(csv.DictReader(fd))


def write_csv_rows(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def resolve_default_knowledge_root(repo_root: Path) -> Path:
    from_env = os.environ.get("GHIDRA_PROJECT_DIR", "").strip()
    if from_env:
        return Path(from_env).expanduser().resolve()
    return (repo_root.parent / "imperialism_knowledge").resolve()


def resolve_anchor_addresses(
    symbols_csv: Path,
    classes: list[str],
) -> tuple[dict[str, str], dict[str, str]]:
    rows = read_pipe_rows(symbols_csv)
    vtable_by_class: dict[str, str] = {}
    classdesc_by_class: dict[str, str] = {}
    for row in rows:
        sym_name = (row.get("name") or "").strip()
        addr = normalize_hex(row.get("address") or "")
        if not sym_name or not addr:
            continue
        for cls in classes:
            if sym_name == f"g_vtbl{cls}":
                vtable_by_class[cls] = addr
            elif sym_name == f"g_pClassDesc{cls}":
                classdesc_by_class[cls] = addr
    return vtable_by_class, classdesc_by_class


def parse_xrefs_csv(stdout_text: str) -> list[dict[str, str]]:
    stream = io.StringIO(stdout_text.strip())
    if not stream.getvalue():
        return []
    reader = csv.DictReader(stream)
    return list(reader)


@dataclass
class CandidateRecord:
    address: str
    suggested_class: str
    name: str = ""
    lane_confidence: dict[str, str] = field(default_factory=dict)
    lane_evidence: dict[str, str] = field(default_factory=dict)

    def merge(self, lane: str, name: str, confidence: str, evidence: str) -> None:
        if name and len(name) > len(self.name):
            self.name = name
        prev_conf = self.lane_confidence.get(lane, "low")
        if CONFIDENCE_RANK.get(confidence, 1) >= CONFIDENCE_RANK.get(prev_conf, 1):
            self.lane_confidence[lane] = confidence
            self.lane_evidence[lane] = evidence

    @property
    def lane_count(self) -> int:
        return len(self.lane_confidence)

    @property
    def confidence(self) -> str:
        if not self.lane_confidence:
            return "low"
        best = max(CONFIDENCE_RANK.get(conf, 1) for conf in self.lane_confidence.values())
        return RANK_TO_CONFIDENCE.get(best, "low")

    @property
    def lanes(self) -> str:
        return "|".join(sorted(self.lane_confidence))

    @property
    def evidence(self) -> str:
        parts: list[str] = []
        for lane in sorted(self.lane_evidence):
            conf = self.lane_confidence.get(lane, "low")
            ev = self.lane_evidence.get(lane, "")
            if ev:
                parts.append(f"{lane}:{conf}:{ev}")
            else:
                parts.append(f"{lane}:{conf}")
        return " ; ".join(parts)

    def score(self) -> int:
        score = 0
        for lane, conf in self.lane_confidence.items():
            if lane == "decomp":
                score += 3
            elif lane == "callers_strict":
                score += 2
            elif lane == "callers_relaxed":
                if conf in {"medium", "high"}:
                    score += 2
            elif lane == "this_passing":
                score += 2
            elif lane == "indirect_refs":
                score += 1
        return score


def load_lane_candidates(
    lane_to_csv: dict[str, Path],
    target_classes: set[str],
) -> dict[tuple[str, str], CandidateRecord]:
    out: dict[tuple[str, str], CandidateRecord] = {}
    for lane, path in lane_to_csv.items():
        for row in read_csv_rows(path):
            class_name = (row.get("class_name") or "").strip()
            if class_name not in target_classes:
                continue
            address = normalize_hex(row.get("address") or "")
            if not address:
                continue
            name = (row.get("name") or "").strip()
            confidence_raw = (row.get("confidence") or "low").strip().lower()
            confidence = confidence_raw if confidence_raw in CONFIDENCE_RANK else "low"
            evidence = (row.get("evidence") or "").strip()
            key = (address, class_name)
            record = out.get(key)
            if record is None:
                record = CandidateRecord(address=address, suggested_class=class_name)
                out[key] = record
            record.merge(lane, name, confidence, evidence)
    return out


def classify_priority(score: int, lane_count: int, confidence: str) -> str:
    confidence_rank = CONFIDENCE_RANK.get(confidence, 1)
    if score >= 7 and lane_count >= 3 and confidence_rank >= CONFIDENCE_RANK["medium"]:
        return "P0"
    if score >= 5 and lane_count >= 2:
        return "P1"
    return "P2"


def write_candidate_methods(
    lane_to_csv: dict[str, Path],
    target_classes: list[str],
    out_path: Path,
    *,
    excluded_addresses: set[int],
) -> tuple[int, int]:
    records = load_lane_candidates(lane_to_csv, set(target_classes))
    rows: list[dict[str, str]] = []
    excluded_count = 0
    for record in records.values():
        score = record.score()
        if score <= 0:
            continue
        address_int = int(record.address, 16)
        if address_int in excluded_addresses:
            excluded_count += 1
            continue
        lane_count = record.lane_count
        confidence = record.confidence
        rows.append(
            {
                "address": record.address,
                "name": record.name,
                "suggested_class": record.suggested_class,
                "score": str(score),
                "priority": classify_priority(score, lane_count, confidence),
                "lane_count": str(lane_count),
                "lanes": record.lanes,
                "confidence": confidence,
                "evidence": record.evidence,
            }
        )
    rows.sort(
        key=lambda row: (
            -int(row["score"]),
            -int(row["lane_count"]),
            row["address"],
            row["suggested_class"],
        )
    )
    write_csv_rows(
        out_path,
        [
            "address",
            "name",
            "suggested_class",
            "score",
            "priority",
            "lane_count",
            "lanes",
            "confidence",
            "evidence",
        ],
        rows,
    )
    return len(rows), excluded_count


def write_vtable_report(
    winners_csv: Path,
    target_classes: list[str],
    anchor_vtables: set[str],
    out_path: Path,
) -> int:
    class_set = set(target_classes)
    rows: list[dict[str, str]] = []
    for row in read_csv_rows(winners_csv):
        vtable_addr = normalize_hex(row.get("vtable_addr") or "")
        if not vtable_addr:
            continue
        winner_class = (row.get("winner_class") or "").strip()
        current_class = (row.get("existing_class_name") or "").strip()
        if (
            winner_class not in class_set
            and current_class not in class_set
            and vtable_addr not in anchor_vtables
        ):
            continue
        anchors = "|".join(
            split_csv_values(row.get("anchor_sources", ""))
            + split_csv_values(row.get("strong_anchor_sources", ""))
        )
        sources = row.get("high_conf_sources", "") or ""
        rows.append(
            {
                "vtable_addr": vtable_addr,
                "current_class": current_class,
                "winner_class": winner_class,
                "winner_score": (row.get("winner_score") or "").strip(),
                "reason": (row.get("reason") or "").strip(),
                "anchors": anchors,
                "sources": sources,
                "accepted": (row.get("accepted") or "").strip(),
            }
        )
    rows.sort(key=lambda row: row["vtable_addr"])
    write_csv_rows(
        out_path,
        [
            "vtable_addr",
            "current_class",
            "winner_class",
            "winner_score",
            "reason",
            "anchors",
            "sources",
            "accepted",
        ],
        rows,
    )
    return len(rows)


def write_constructor_report(
    xref_rows: list[dict[str, str]],
    vtable_addrs: set[str],
    out_path: Path,
) -> int:
    out_rows: list[dict[str, str]] = []
    for row in xref_rows:
        target_addr = normalize_hex(row.get("target_addr") or "")
        if target_addr not in vtable_addrs:
            continue
        fn_addr = normalize_hex(row.get("function_addr") or "")
        fn_name = (row.get("function_name") or "").strip()
        instruction = (row.get("instruction") or "").strip()
        if not fn_addr or not fn_name or fn_name == "<no_func>":
            continue
        out_rows.append(
            {
                "vtable_addr": target_addr,
                "constructor_addr": fn_addr,
                "constructor_name": fn_name,
                "write_instruction": instruction,
            }
        )
    out_rows.sort(key=lambda row: (row["vtable_addr"], row["constructor_addr"]))
    write_csv_rows(
        out_path,
        ["vtable_addr", "constructor_addr", "constructor_name", "write_instruction"],
        out_rows,
    )
    return len(out_rows)


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    default_knowledge_root = resolve_default_knowledge_root(repo_root)
    parser = argparse.ArgumentParser(
        description="Run read-only class/vtable discovery lanes and aggregate results.",
    )
    parser.add_argument(
        "--knowledge-root",
        default=str(default_knowledge_root),
        help="Path to imperialism_knowledge repository (default: GHIDRA_PROJECT_DIR or ../imperialism_knowledge).",
    )
    parser.add_argument(
        "--project-root",
        default="",
        help="Ghidra project root passed to impk commands (default: --knowledge-root).",
    )
    parser.add_argument(
        "--symbols-csv",
        default=str(repo_root / "config" / "symbols.csv"),
        help="Pipe-delimited symbols.csv used for class anchor addresses.",
    )
    parser.add_argument(
        "--ownership-csv",
        default=str(repo_root / DEFAULT_FUNCTION_OWNERSHIP_CSV),
        help="Function ownership CSV used to exclude already-owned manual addresses from candidate output.",
    )
    parser.add_argument(
        "--classes",
        default="TGreatPower,TAutoGreatPower",
        help="Comma-separated class list.",
    )
    parser.add_argument(
        "--out-dir",
        default="tmp_decomp/class_discovery",
        help="Output directory relative to knowledge root unless absolute.",
    )
    parser.add_argument(
        "--macos-csv",
        default="tmp_decomp/macos_class_methods.csv",
        help="macOS methods CSV relative to knowledge root unless absolute.",
    )
    parser.add_argument(
        "--skip-wave",
        action="store_true",
        help="Skip run_windows_class_recovery_wave (use existing winners/conflicts CSV if present).",
    )
    parser.add_argument(
        "--include-owned-candidates",
        action="store_true",
        help="Include addresses that are already owned manually in candidate_methods output.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    knowledge_root = resolve_repo_path(repo_root, args.knowledge_root)
    if not knowledge_root.is_dir():
        raise SystemExit(f"knowledge root does not exist: {knowledge_root}")
    project_root = resolve_repo_path(repo_root, args.project_root) if args.project_root else knowledge_root
    symbols_csv = resolve_repo_path(repo_root, args.symbols_csv)
    if not symbols_csv.is_file():
        raise SystemExit(f"symbols CSV not found: {symbols_csv}")
    ownership_csv = resolve_repo_path(repo_root, args.ownership_csv)

    classes = parse_classes(args.classes)
    slug = class_slug(classes)
    base_out_dir = Path(args.out_dir)
    if not base_out_dir.is_absolute():
        base_out_dir = knowledge_root / base_out_dir
    run_dir = base_out_dir.resolve() / slug
    run_dir.mkdir(parents=True, exist_ok=True)

    macos_csv = Path(args.macos_csv)
    if not macos_csv.is_absolute():
        macos_csv = (knowledge_root / macos_csv).resolve()

    vtable_by_class, classdesc_by_class = resolve_anchor_addresses(symbols_csv, classes)
    vtable_addrs = sorted(vtable_by_class.values())
    classdesc_addrs = sorted(classdesc_by_class.values())
    all_anchor_addrs = sorted(set(vtable_addrs + classdesc_addrs))

    print("[info] classes:", ", ".join(classes))
    print("[info] knowledge_root:", knowledge_root)
    print("[info] project_root:", project_root)
    print("[info] output:", run_dir)
    if not all_anchor_addrs:
        print("[warn] no class anchor addresses found in symbols.csv")
    excluded_manual_addresses: set[int] = set()
    if not args.include_owned_candidates and ownership_csv.is_file():
        ownership_rows = load_function_ownership(ownership_csv)
        excluded_manual_addresses = {
            address
            for address, row in ownership_rows.items()
            if row.ownership.strip().lower() != "autogen"
        }
        print(
            "[info] excluding manually owned addresses from candidates:",
            len(excluded_manual_addresses),
            f"(source: {ownership_csv})",
        )
    elif not args.include_owned_candidates and not ownership_csv.is_file():
        print(f"[warn] ownership CSV not found; no address exclusion: {ownership_csv}")

    lane_paths = {
        "callers_strict": run_dir / "infer_callers_strict.csv",
        "callers_relaxed": run_dir / "infer_callers_relaxed.csv",
        "decomp": run_dir / "infer_decomp.csv",
        "this_passing": run_dir / "infer_this_passing.csv",
        "indirect_refs": run_dir / "infer_indirect_refs.csv",
    }
    static_vtables_csv = run_dir / "windows_static_vtables.csv"
    slot_func_names_csv = run_dir / "vtable_slot_func_names.csv"
    windows_runtime_slot_writes_csv = run_dir / "windows_runtime_vtable_slot_writes.csv"
    windows_runtime_slot_map_csv = run_dir / "windows_runtime_vtable_slot_map.csv"
    ctor_xrefs_csv = run_dir / "vtable_ctor_xrefs.csv"
    slot_ownership_csv = run_dir / "vtable_slot_ownership.csv"
    slot_ownership_macos_csv = run_dir / "vtable_slot_ownership_macos.csv"
    ctor_stores_csv = run_dir / "vtable_ctor_stores.csv"
    ctor_name_csv = run_dir / "vtable_ctor_name.csv"
    slot_overlap_csv = run_dir / "vtable_slot_overlap.csv"
    macos_slot_count_csv = run_dir / "vtable_macos_slot_count.csv"
    matrix_csv = run_dir / "windows_vtable_evidence_matrix.csv"
    winners_csv = run_dir / "windows_vtable_winners.csv"
    conflicts_csv = run_dir / "windows_vtable_conflicts.csv"
    relabel_csv = run_dir / "windows_vtable_relabel.csv"
    base_labels_apply_csv = run_dir / "base_labels_apply.csv"
    attach_apply_csv = run_dir / "attach_apply.csv"
    rename_only_apply_csv = run_dir / "rename_only_apply.csv"
    move_global_apply_csv = run_dir / "move_global_apply.csv"
    relabel_report_csv = run_dir / "relabel_report.csv"
    anchor_xrefs_csv = run_dir / "anchor_xrefs_raw.csv"
    candidate_methods_csv = run_dir / "candidate_methods.csv"
    vtable_report_csv = run_dir / "vtable_report.csv"
    constructor_report_csv = run_dir / "constructor_report.csv"
    summary_json = run_dir / "summary.json"

    # Class membership lanes.
    run_impk(
        knowledge_root,
        [
            "infer_class_from_callers",
            "--out-csv",
            str(lane_paths["callers_strict"]),
            "--min-callers",
            "2",
            "--min-ratio",
            "0.67",
            "--caller-depth",
            "2",
            "--project-root",
            str(project_root),
        ],
    )
    run_impk(
        knowledge_root,
        [
            "infer_class_from_callers",
            "--out-csv",
            str(lane_paths["callers_relaxed"]),
            "--min-callers",
            "1",
            "--min-ratio",
            "0.50",
            "--caller-depth",
            "2",
            "--project-root",
            str(project_root),
        ],
    )
    run_impk(
        knowledge_root,
        [
            "infer_class_from_decomp",
            "--out-csv",
            str(lane_paths["decomp"]),
            "--project-root",
            str(project_root),
        ],
    )
    run_impk(
        knowledge_root,
        [
            "infer_class_from_this_passing",
            "--out-csv",
            str(lane_paths["this_passing"]),
            "--min-votes",
            "1",
            "--min-ratio",
            "0.67",
            "--project-root",
            str(project_root),
        ],
    )
    run_impk(
        knowledge_root,
        [
            "infer_class_from_indirect_refs",
            "--out-csv",
            str(lane_paths["indirect_refs"]),
            "--project-root",
            str(project_root),
        ],
    )

    # Vtable lanes.
    run_impk(
        knowledge_root,
        [
            "scan_windows_static_vtables",
            "--out-csv",
            str(static_vtables_csv),
            "--project-root",
            str(project_root),
        ],
    )
    run_impk(
        knowledge_root,
        [
            "attribute_vtables_from_slot_func_names",
            "--windows-static-vtables-csv",
            str(static_vtables_csv),
            "--out-csv",
            str(slot_func_names_csv),
            "--project-root",
            str(project_root),
        ],
    )
    if macos_csv.exists():
        run_impk(
            knowledge_root,
            [
                "attribute_vtables_from_slot_ownership",
                "--windows-static-vtables-csv",
                str(static_vtables_csv),
                "--macos-csv",
                str(macos_csv),
                "--out-csv",
                str(slot_ownership_macos_csv),
                "--confidence-filter",
                "all",
                "--project-root",
                str(project_root),
            ],
        )
    else:
        print(f"[warn] macOS CSV not found: {macos_csv}")

    if not args.skip_wave:
        wave_cmd = [
            "run_windows_class_recovery_wave",
            "--skip-scan",
            "--skip-bsim",
            "--windows-static-vtables-csv",
            str(static_vtables_csv),
            "--windows-runtime-slot-writes-csv",
            str(windows_runtime_slot_writes_csv),
            "--windows-runtime-slot-map-csv",
            str(windows_runtime_slot_map_csv),
            "--matrix-csv",
            str(matrix_csv),
            "--winners-csv",
            str(winners_csv),
            "--conflicts-csv",
            str(conflicts_csv),
            "--relabel-csv",
            str(relabel_csv),
            "--base-labels-apply-csv",
            str(base_labels_apply_csv),
            "--attach-apply-csv",
            str(attach_apply_csv),
            "--rename-only-apply-csv",
            str(rename_only_apply_csv),
            "--move-global-apply-csv",
            str(move_global_apply_csv),
            "--report-csv",
            str(relabel_report_csv),
            "--constructor-xrefs-csv",
            str(ctor_xrefs_csv),
            "--slot-ownership-csv",
            str(slot_ownership_csv),
            "--ctor-stores-csv",
            str(ctor_stores_csv),
            "--ctor-name-csv",
            str(ctor_name_csv),
            "--slot-overlap-csv",
            str(slot_overlap_csv),
            "--macos-slot-count-csv",
            str(macos_slot_count_csv),
            "--confidence-filter",
            "low",
            "--project-root",
            str(project_root),
        ]
        run_impk(knowledge_root, wave_cmd)

    if not winners_csv.exists():
        raise SystemExit(f"Winners CSV missing; expected at {winners_csv}")

    # Anchor xrefs / constructor probes.
    xref_rows: list[dict[str, str]] = []
    if all_anchor_addrs:
        xref_output = run_impk(
            knowledge_root,
            [
                "list_xrefs_to_address",
                *all_anchor_addrs,
            ],
            capture_output=True,
        )
        anchor_xrefs_csv.write_text(xref_output, encoding="utf-8")
        xref_rows = parse_xrefs_csv(xref_output)

    candidate_count, excluded_candidate_count = write_candidate_methods(
        lane_paths,
        classes,
        candidate_methods_csv,
        excluded_addresses=excluded_manual_addresses,
    )
    vtable_count = write_vtable_report(
        winners_csv,
        classes,
        set(vtable_addrs),
        vtable_report_csv,
    )
    ctor_count = write_constructor_report(
        xref_rows,
        set(vtable_addrs),
        constructor_report_csv,
    )

    summary = {
        "classes": classes,
        "knowledge_root": str(knowledge_root),
        "project_root": str(project_root),
        "run_dir": str(run_dir),
        "anchors": {
            "vtable_by_class": vtable_by_class,
            "classdesc_by_class": classdesc_by_class,
        },
        "outputs": {
            "candidate_methods_csv": str(candidate_methods_csv),
            "vtable_report_csv": str(vtable_report_csv),
            "constructor_report_csv": str(constructor_report_csv),
            "winners_csv": str(winners_csv),
            "conflicts_csv": str(conflicts_csv),
            "relabel_csv": str(relabel_csv),
            "slot_func_names_csv": str(slot_func_names_csv),
            "slot_ownership_macos_csv": str(slot_ownership_macos_csv),
            "anchor_xrefs_csv": str(anchor_xrefs_csv),
        },
        "counts": {
            "candidate_methods": candidate_count,
            "excluded_owned_candidates": excluded_candidate_count,
            "vtable_rows": vtable_count,
            "constructor_rows": ctor_count,
        },
    }
    summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    print(f"[saved] {candidate_methods_csv} rows={candidate_count}")
    print(f"[saved] excluded owned candidates={excluded_candidate_count}")
    print(f"[saved] {vtable_report_csv} rows={vtable_count}")
    print(f"[saved] {constructor_report_csv} rows={ctor_count}")
    print(f"[saved] {summary_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
