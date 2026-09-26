"""Shared native reccmp reports with complete symbol pairing."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from reccmp.compare import Compare
from reccmp.compare.report import ReccmpStatusReport, serialize_reccmp_report
from reccmp.project.detect import RecCmpProject


def run_report(
    target: str,
    build_dir: Path,
    *,
    diet: bool = False,
    orig_addresses: Iterable[int] = (),
    recomp_addresses: Iterable[int] = (),
) -> list[dict]:
    """Pair every symbol, then compare only the requested addresses.

    Loading only requested PDB modules can leave their callees unpaired and
    produce false call-target mismatches. Full symbol setup also makes results
    independent of whether a previous invocation populated reccmp's full cache.
    """
    project_target = RecCmpProject.from_directory(build_dir.resolve()).get(target)
    compare = Compare.from_target(project_target)
    originals = sorted(set(orig_addresses))
    recompiled = sorted(set(recomp_addresses))
    if originals or recompiled:
        report = ReccmpStatusReport(
            filename=project_target.original_path.name,
            source_digest=compare.orig_source_digest,
        )
        for entity in compare.compare_addresses(
            originals, recompiled, include_diff=not diet, include_exact_diff=False
        ):
            report.add_match(entity)
    else:
        report = compare.to_report(
            project_target.original_path.name,
            include_diff=not diet,
            include_exact_diff=False,
        )
    report.asmcmp_filtering(False, project_target.report_config.ignore_functions)
    return json.loads(serialize_reccmp_report(report, diff_included=not diet))["data"]
