#!/usr/bin/env python3
"""Warn when a committed reccmp baseline snapshot may not reflect the working tree.

`func_status`/`port_candidates` read `config/reccmp_progress_baseline.report.json` —
a snapshot written by `just stats-baseline-update` — with no signal that it might be
stale relative to uncommitted edits. This is a cheap, advisory `git status` check
shared by both callers; it is not a correctness gate.
"""

from __future__ import annotations

import sys
from pathlib import Path

from tools.common.repo import dirty_tracked_paths

WATCH_PATHS = ["src", "include", "config/symbols.csv"]


def warn_if_baseline_stale(repo_root: Path) -> None:
    dirty = dirty_tracked_paths(repo_root, WATCH_PATHS)
    if not dirty:
        return
    print(
        f"NOTE: {len(dirty)} tracked source/config path(s) have uncommitted changes; "
        "scores below reflect the last `just stats-baseline-update`, not your current edits.",
        file=sys.stderr,
    )
