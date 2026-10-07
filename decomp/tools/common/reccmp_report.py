"""Compose current reccmp/Ghidriff runs; retain their native evidence artifacts."""

from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
import sys
from collections import Counter
from pathlib import Path

from reccmp.compare import Compare
from reccmp.compare.manifest import build_manifest
from reccmp.compare.variables import CompareResult
from reccmp.compare.vtables import SlotStatus, compare_vtable
from reccmp.ghidriff.report import selected_comparison
from reccmp.ghidriff.results import Outcome
from reccmp.project.detect import RecCmpProject
from reccmp.types import EntityType, ImageId

from tools.common import ghidra_env


def load_catalog(target: str, build_dir: Path) -> Compare:
    project_target = RecCmpProject.from_directory(build_dir.resolve()).get(target)
    return Compare.from_target(project_target)


def read_summary(report: Path) -> dict:
    path = report / "summary.json" if report.is_dir() else report
    summary = json.loads(path.read_text(encoding="utf-8"))
    addresses = [int(row["orig"], 16) for row in summary["functions"]]
    if len(addresses) != len(set(addresses)):
        raise ValueError(f"Duplicate original function addresses in {path}")
    valid = {outcome.value for outcome in Outcome}
    if any(row["outcome"] not in valid for row in summary["functions"]):
        raise ValueError(f"Unknown comparison outcome in {path}")
    return summary


ANALYZED = frozenset({Outcome.DIFFERENCES.value, Outcome.NO_DIFFERENCES.value})


def similarity(row: dict) -> float | None:
    """Score of the producer-selected pass for an analyzed function."""
    if row["outcome"] not in ANALYZED:
        return None
    score = selected_comparison(row)["similarity"]
    return None if score is None else float(score)


def function_counts(rows: list[dict]) -> dict:
    counts = Counter(row["outcome"] for row in rows)
    retried = [row for row in rows if row["selected_pass"] == "inline"]
    analyzed = [row for row in rows if row["outcome"] in ANALYZED]
    evidence = [selected_comparison(row) for row in analyzed]
    scores = [score for row in analyzed if (score := similarity(row)) is not None]
    return {
        "outcomes": {outcome.value: counts[outcome.value] for outcome in Outcome},
        "clean_rate": (
            counts[Outcome.NO_DIFFERENCES.value] / len(analyzed) if analyzed else None
        ),
        "similarity": {
            "mean": statistics.fmean(scores) if scores else None,
            "median": statistics.median(scores) if scores else None,
            "scored": len(scores),
            "unscored": len(analyzed) - len(scores),
        },
        "code_differences": sum(bool(item.get("body_diff")) for item in evidence),
        "data_differences": sum(bool(item.get("data")) for item in evidence),
        # Inferred declarations differ independently of body quality.
        "signature_differences": sum(
            bool(selected_comparison(row)["signature_diff"]) for row in rows
        ),
        "scalar_signedness_differences": sum(
            item.get("change_kind") == "scalar-signedness" for item in evidence
        ),
        "inline_retries": len(retried),
        "inline_retries_clean": sum(
            row["outcome"] == Outcome.NO_DIFFERENCES.value for row in retried
        ),
    }


def diagnostic_results(catalog: Compare) -> dict:
    data = []
    for variable in catalog.get_variables():
        item = catalog.variable_comparator.compare_variable(variable)
        data.append(
            {
                "orig": hex(item.orig_addr),
                "recomp": hex(item.recomp_addr),
                "name": item.name,
                "result": item.result.name.lower(),
                "error": item.error,
                "offsets": [
                    {
                        "offset": offset.offset,
                        "name": offset.name,
                        "match": offset.match,
                        "orig": str(offset.values[0]),
                        "recomp": str(offset.values[1]),
                    }
                    for offset in item.compared
                ],
            }
        )
    aliases = {
        alias.orig_addr: canonical
        for alias, canonical in catalog.get_aliases(ImageId.ORIG)
        if alias.entity_type == EntityType.VTABLE and alias.orig_addr is not None
    }
    tables = []
    for entity in catalog.get_all():
        if entity.entity_type != EntityType.VTABLE or entity.orig_addr is None:
            continue
        if entity.orig_addr in aliases:
            continue
        match = catalog.get_match(entity.orig_addr)
        if match is None:
            tables.append(
                {
                    "orig": hex(entity.orig_addr),
                    "name": entity.name,
                    "outcome": "unpaired",
                    "slots": [],
                }
            )
            continue
        comparison = compare_vtable(
            catalog.db, catalog.orig_bin, catalog.recomp_bin, match
        )
        slots = [
            {"offset": slot.offset, "outcome": slot.status.value}
            for slot in comparison.slots
        ]
        if comparison.matches:
            outcome = "match"
        elif any(slot.status == SlotStatus.DIFFERENT for slot in comparison.slots):
            outcome = "different"
        else:
            outcome = "unpaired"
        tables.append(
            {
                "orig": hex(match.orig_addr),
                "recomp": hex(match.recomp_addr),
                "name": match.name,
                "outcome": outcome,
                "slots": slots,
            }
        )
    data_counts = Counter(row["result"] for row in data)
    table_counts = Counter(row["outcome"] for row in tables)
    return {
        "datacmp": {
            "counts": {
                result.name.lower(): data_counts[result.name.lower()]
                for result in CompareResult
            },
            "issues": sum(row["result"] != "match" for row in data),
            "variables": data,
        },
        "vtables": {
            "counts": {
                outcome: table_counts[outcome]
                for outcome in ("match", "different", "unpaired")
            },
            "tables": tables,
            "aliases": [
                {
                    "orig": hex(address),
                    "canonical": hex(canonical.orig_addr),
                    "recomp": hex(canonical.recomp_addr),
                }
                for address, canonical in sorted(aliases.items())
            ],
        },
    }


def run_report(
    target: str,
    build_dir: Path,
    *,
    orig_addresses: list[int],
    output: Path,
    selection: dict,
) -> dict:
    if not orig_addresses:
        raise ValueError("No authored functions selected")
    if output.exists():
        raise ValueError(f"Report directory already exists: {output}")
    ghidra_env.load_dotenv()
    ghidra_env.enforce_versions(ghidra_env.install_dir())
    project = Path(ghidra_env.project_location()) / (ghidra_env.project_name() + ".gpr")
    if not project.is_file():
        raise FileNotFoundError(
            "Reviewed Ghidra project is missing; run just restore-project"
        )
    project_target = RecCmpProject.from_directory(build_dir.resolve()).get(target)
    input_paths = {
        "orig": project_target.original_path,
        "recomp": project_target.recompiled_path,
        "pdb": project_target.recompiled_pdb,
    }
    if project_target.source_index is not None:
        input_paths["source_index"] = project_target.source_index
    input_hashes = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in input_paths.items()
    }
    wanted = set(orig_addresses)
    manifest = build_manifest(
        Compare.from_target(project_target, orig_addrs=sorted(wanted)),
        target_id=project_target.target_id,
        orig_path=project_target.original_path,
        recomp_path=project_target.recompiled_path,
        select=lambda entity: entity.orig_addr in wanted,
    )
    selected = {entry.orig_addr for entry in manifest.functions}
    if selected != wanted:
        raise ValueError(
            f"Selection differs from the catalog: missing={sorted(wanted - selected)}, "
            f"unexpected={sorted(selected - wanted)}"
        )
    ghidra_env._evict_daemon_if_running()
    repo = Path(__file__).resolve().parents[2]
    argv = [
        sys.executable,
        "-m",
        "reccmp.tools.compare",
        "--manifest",
        str((output / "manifest.json").resolve()),
        "--output",
        str(output.resolve()),
        "--ghidra-projects",
        str(repo / "build/reccmp-ghidra"),
        "--orig-ghidra-project",
        str(project),
        "--orig-ghidra-program",
        "/" + ghidra_env.program_name().lstrip("/"),
    ]
    output.mkdir(parents=True)
    (output / "selection.json").write_text(json.dumps(selection, indent=1) + "\n")
    # reccmp revalidates both binary hashes before analyzing this frozen pairing.
    (output / "manifest.json").write_text(
        json.dumps(manifest.to_json(), indent=1) + "\n"
    )
    with (output / "compare.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(
            argv,
            cwd=build_dir.resolve(),
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if result.returncode:
        raise RuntimeError(
            f"reccmp failed ({result.returncode}); inspect {output / 'compare.log'}"
        )
    summary = read_summary(output)
    if any(
        hashlib.sha256(path.read_bytes()).hexdigest() != input_hashes[name]
        for name, path in input_paths.items()
    ):
        raise ValueError("Comparison inputs changed during the run")
    if any(
        summary["inputs"][image]["sha256"] != input_hashes[image]
        for image in ("orig", "recomp")
    ):
        raise ValueError("Native report used different input binaries")
    actual = {int(row["orig"], 16) for row in summary["functions"]}
    if actual != wanted:
        raise ValueError(
            f"Selection differs from the catalog: missing={sorted(wanted - actual)}, "
            f"unexpected={sorted(actual - wanted)}"
        )
    checks = diagnostic_results(load_catalog(target, build_dir))
    checks["input_sha256"] = input_hashes
    (output / "checks.json").write_text(json.dumps(checks, indent=1) + "\n")
    return summary
