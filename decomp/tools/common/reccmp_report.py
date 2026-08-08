#!/usr/bin/env python3
"""Shared runner for structured reccmp JSON reports.

Several tools each shelled out to `reccmp-reccmp --json` with their own
temp-file plumbing (compare_batch, global_xref_oracle, triage, stackcmp_triage).
This is the one copy. `diet=True` (scores only) is enough for score filtering;
`diet=False` additionally includes the per-function asm diffs the mining tools
need.

(progress_stats keeps its specialized invocation for baseline handling.)
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path


def run_report(
    target: str,
    build_dir: Path,
    *,
    diet: bool = False,
    orig_addresses: Iterable[int] = (),
    recomp_addresses: Iterable[int] = (),
) -> list[dict]:
    """Run reccmp once and return the report's `data` list.

    Address filters are applied inside reccmp, before disassembly and semantic
    verification.  This keeps targeted tools fresh without paying for a full
    corpus report or relying on a stale cache.
    """
    with tempfile.TemporaryDirectory(prefix="imperialism-reccmp-") as temp_dir:
        json_path = Path(temp_dir) / "report.json"
        cmd = [
            "uv",
            "run",
            "reccmp-reccmp",
            "--target",
            target,
            "--json",
            str(json_path),
            "--silent",
        ]
        if diet:
            cmd.append("--json-diet")
        for address in sorted(set(orig_addresses)):
            cmd.extend(("--orig-address", hex(address)))
        for address in sorted(set(recomp_addresses)):
            cmd.extend(("--recomp-address", hex(address)))
        try:
            subprocess.run(
                cmd,
                cwd=build_dir,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as error:
            if error.stderr:
                print(error.stderr, file=sys.stderr, end="")
            raise
        return json.loads(json_path.read_text())["data"]
