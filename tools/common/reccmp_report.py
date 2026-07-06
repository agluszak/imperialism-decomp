#!/usr/bin/env python3
"""Shared runner for the full reccmp JSON report.

Several tools each shelled out to `reccmp-reccmp --json` with their own
temp-file plumbing (compare_batch, global_xref_oracle, triage, stackcmp_triage).
This is the one copy. `diet=True` (scores only, ~4s) is enough for score
filtering; `diet=False` additionally includes the per-function asm diffs the
mining tools need.

(progress_stats and addr_translate keep their own specialized invocations —
they layer caching/baseline handling on top.)
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


def run_report(target: str, build_dir: Path, *, diet: bool = False) -> list[dict]:
    """Run reccmp once and return the report's `data` list."""
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        json_path = tf.name
    cmd = ["uv", "run", "reccmp-reccmp", "--target", target, "--json", json_path, "--silent"]
    if diet:
        cmd.append("--json-diet")
    subprocess.run(cmd, cwd=build_dir, check=True, stdout=subprocess.DEVNULL)
    return json.loads(Path(json_path).read_text())["data"]
