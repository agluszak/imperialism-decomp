#!/usr/bin/env python3
"""Compare parsed W32Dasm ALF xrefs against the read-only Ghidra project."""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter
from pathlib import Path

import pyghidra

from tools.w32dasm.parse_alf import DEFAULT_ALF, DEFAULT_OUT_DIR, parse_alf

PROJECT_LOCATION = os.getenv(
    "GHIDRA_PROJECT_DIR", str(Path(__file__).resolve().parents[2] / "vendor" / "ghidra")
)
PROJECT_NAME = os.getenv("GHIDRA_PROJECT_NAME", "imperialism-decomp")
PROGRAM_NAME = os.getenv("GHIDRA_PROGRAM_NAME", "Imperialism.exe")
INSTALL_DIR = os.getenv("GHIDRA_INSTALL_DIR")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alf", type=Path, default=DEFAULT_ALF, help="W32Dasm .alf file")
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_OUT_DIR, help="Parsed/report output directory")
    parser.add_argument(
        "--max-sample-rows",
        type=int,
        default=500,
        help="Maximum rows to write for each sample mismatch CSV",
    )
    return parser.parse_args()


def parse_addr(text: str) -> int:
    stripped = text.strip()
    return int(stripped[2:] if stripped.lower().startswith("0x") else stripped, 16)


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_code_ranges(section_path: Path, image_base: int) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for row in load_rows(section_path):
        flags = int(row["flags"], 16)
        if row["name"] != ".text" and (flags & 0x20000000) == 0:
            continue
        start = image_base + int(row["rva"], 16)
        end = start + int(row["size"], 16)
        ranges.append((start, end, row["name"]))
    return ranges


def in_ranges(address: int, ranges: list[tuple[int, int, str]]) -> bool:
    return any(start <= address < end for start, end, _name in ranges)


def ensure_parsed(alf_path: Path, report_dir: Path) -> None:
    required = ["sections.csv", "instructions.csv", "xrefs.csv", "summary.json"]
    if not all((report_dir / name).exists() for name in required):
        parse_alf(alf_path, report_dir)


def write_rows(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def addr_obj(space, addr: int):
    return space.getAddress(f"{addr:08X}")


def append_instruction_cluster(
    clusters: list[dict[str, object]],
    cluster: dict[str, object] | None,
) -> None:
    if cluster is not None:
        clusters.append(cluster)


def main() -> int:
    args = parse_args()
    ensure_parsed(args.alf, args.report_dir)
    args.report_dir.mkdir(parents=True, exist_ok=True)

    instruction_rows = load_rows(args.report_dir / "instructions.csv")
    xref_rows = load_rows(args.report_dir / "xrefs.csv")

    pyghidra.start(install_dir=Path(INSTALL_DIR) if INSTALL_DIR else None)
    project = pyghidra.open_project(PROJECT_LOCATION, PROJECT_NAME, create=False)

    from java.lang import Object as JavaObject

    consumer = JavaObject()
    program = None
    try:
        program_path = PROGRAM_NAME if PROGRAM_NAME.startswith("/") else f"/{PROGRAM_NAME}"
        domain_file = project.getProjectData().getFile(program_path)
        if domain_file is None:
            raise FileNotFoundError(f'Program "{PROGRAM_NAME}" not found in project.')
        program = domain_file.getReadOnlyDomainObject(consumer, -1, pyghidra.task_monitor())

        space = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        functions = program.getFunctionManager()
        references = program.getReferenceManager()
        image_base = int(program.getImageBase().getOffset())
        code_ranges = load_code_ranges(args.report_dir / "sections.csv", image_base)

        instruction_counts: Counter[str] = Counter()
        instruction_samples: list[dict[str, object]] = []
        instruction_clusters: list[dict[str, object]] = []
        current_cluster: dict[str, object] | None = None
        for row in instruction_rows:
            address = parse_addr(row["address"])
            if not in_ranges(address, code_ranges):
                instruction_counts["skipped_non_code_section"] += 1
                continue
            ghidra_address = addr_obj(space, address)
            instruction = listing.getInstructionAt(ghidra_address)
            function = functions.getFunctionContaining(ghidra_address)
            if instruction is None:
                instruction_counts["missing_instruction"] += 1
                issue = "missing_instruction"
                if len(instruction_samples) < args.max_sample_rows:
                    instruction_samples.append(
                        {
                            "address": row["address"],
                            "alf_text": row["text"],
                            "issue": issue,
                        }
                    )
            elif function is None:
                instruction_counts["outside_function"] += 1
                issue = "outside_function"
                if len(instruction_samples) < args.max_sample_rows:
                    instruction_samples.append(
                        {
                            "address": row["address"],
                            "alf_text": row["text"],
                            "issue": issue,
                        }
                    )
            else:
                instruction_counts["inside_function"] += 1
                append_instruction_cluster(instruction_clusters, current_cluster)
                current_cluster = None
                continue

            if (
                current_cluster is not None
                and current_cluster["issue"] == issue
                and address - int(current_cluster["end_address"], 16) <= 16
            ):
                current_cluster["end_address"] = f"0x{address:08X}"
                current_cluster["instruction_count"] = int(current_cluster["instruction_count"]) + 1
                current_cluster["last_text"] = row["text"]
            else:
                append_instruction_cluster(instruction_clusters, current_cluster)
                current_cluster = {
                    "start_address": row["address"],
                    "end_address": row["address"],
                    "issue": issue,
                    "instruction_count": 1,
                    "first_text": row["text"],
                    "last_text": row["text"],
                }
        append_instruction_cluster(instruction_clusters, current_cluster)

        ref_cache: dict[int, set[int]] = {}
        xref_counts: Counter[str] = Counter()
        missing_xrefs: list[dict[str, object]] = []
        for row in xref_rows:
            source = parse_addr(row["ref_address"])
            target = parse_addr(row["target_address"])
            if target not in ref_cache:
                target_refs: set[int] = set()
                iterator = references.getReferencesTo(addr_obj(space, target))
                while iterator.hasNext():
                    target_refs.add(int(iterator.next().getFromAddress().getOffset()))
                ref_cache[target] = target_refs

            if source in ref_cache[target]:
                xref_counts["matched"] += 1
            else:
                xref_counts["missing_in_ghidra"] += 1
                missing_xrefs.append(
                    {
                        "target_address": row["target_address"],
                        "ref_address": row["ref_address"],
                        "kind": row["kind"],
                        "jump_hint": row["jump_hint"],
                        "detail": row["detail"],
                    }
                )

        write_rows(
            args.report_dir / "instructions_not_in_ghidra_functions.csv",
            ["address", "alf_text", "issue"],
            instruction_samples,
        )
        write_rows(
            args.report_dir / "xrefs_missing_in_ghidra.csv",
            ["target_address", "ref_address", "kind", "jump_hint", "detail"],
            missing_xrefs,
        )
        write_rows(
            args.report_dir / "instruction_gap_clusters.csv",
            ["start_address", "end_address", "issue", "instruction_count", "first_text", "last_text"],
            instruction_clusters,
        )

        summary = {
            "alf": str(args.alf),
            "report_dir": str(args.report_dir),
            "ghidra_project_dir": str(PROJECT_LOCATION),
            "ghidra_project_name": PROJECT_NAME,
            "ghidra_program_name": PROGRAM_NAME,
            "instruction_counts": dict(instruction_counts),
            "code_ranges": [
                {"start": f"0x{start:08X}", "end": f"0x{end:08X}", "section": name}
                for start, end, name in code_ranges
            ],
            "xref_counts": dict(xref_counts),
            "unique_xref_targets_checked": len(ref_cache),
            "sample_limit": args.max_sample_rows,
            "outputs": {
                "instruction_samples": str(args.report_dir / "instructions_not_in_ghidra_functions.csv"),
                "xref_samples": str(args.report_dir / "xrefs_missing_in_ghidra.csv"),
                "instruction_gap_clusters": str(args.report_dir / "instruction_gap_clusters.csv"),
            },
        }
        (args.report_dir / "compare_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n"
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
    finally:
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
