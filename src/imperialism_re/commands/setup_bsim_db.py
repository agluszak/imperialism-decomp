#!/usr/bin/env python3
"""
One-time BSim H2 database creation and signature ingestion for all programs in the project.

Calls the Ghidra ``bsim`` CLI tool as subprocesses to:
  1. Create an H2 database:     bsim createdatabase file://<db_path> medium_nosize
  2. Generate signatures:       bsim generatesigs ghidra:<project_url> <sigs_dir> --bsim file://<db_path>
  3. Commit signatures:         bsim commitsigs file://<db_path> <sigs_dir>

``generatesigs`` processes ALL programs in the Ghidra project in one pass
(both Imperialism.exe and Imperialism Demo.exe).

IMPORTANT: Close the Ghidra GUI before running this command — the local project
has a single-writer lock, and the bsim headless tool needs exclusive access.

Usage:
  uv run impk setup_bsim_db
  uv run impk setup_bsim_db --force-recreate
  uv run impk setup_bsim_db --db-dir /tmp/bsim_db --sigs-dir /tmp/bsim_sigs
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

from imperialism_re.core.config import default_project_root, get_runtime_config, resolve_project_root


def _run(cmd: list[str]) -> int:
    """Run a subprocess, streaming stdout/stderr; return exit code."""
    print(f"\n[run] {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd)
    return result.returncode


def main() -> int:
    ap = argparse.ArgumentParser(
        description="One-time BSim H2 database creation and signature ingestion.",
    )
    ap.add_argument(
        "--db-dir",
        default=None,
        help="Directory for H2 database files (default: <project_root>/bsim_db)",
    )
    ap.add_argument(
        "--sigs-dir",
        default=None,
        help="Directory for signature XML files (default: <project_root>/bsim_sigs)",
    )
    ap.add_argument(
        "--force-recreate",
        action="store_true",
        help="Delete and recreate the database if it already exists",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    cfg = get_runtime_config(root)
    ghidra_bsim = cfg.ghidra_dir / "support" / "bsim"

    if not ghidra_bsim.exists():
        print(f"[error] bsim CLI not found: {ghidra_bsim}")
        print(f"  Expected at: {ghidra_bsim}")
        print(f"  Set IMPK_GHIDRA_DIR env var if Ghidra is installed elsewhere.")
        return 1

    db_dir = Path(args.db_dir) if args.db_dir else root / "bsim_db"
    sigs_dir = Path(args.sigs_dir) if args.sigs_dir else root / "bsim_sigs"
    db_path = db_dir / "imperialism"
    db_url = f"file://{db_path}"

    # Local project URL for generatesigs: ghidra:<absolute_project_dir>/<project_name>
    # e.g. ghidra:<project_root>/imperialism-decomp
    project_url = f"ghidra:{root}/{cfg.project_name}"

    print(f"[config] ghidra_bsim = {ghidra_bsim}")
    print(f"[config] db_dir      = {db_dir}")
    print(f"[config] sigs_dir    = {sigs_dir}")
    print(f"[config] db_url      = {db_url}")
    print(f"[config] project_url = {project_url}")

    # Handle existing database
    mv_db = db_dir / "imperialism.mv.db"
    if mv_db.exists():
        if args.force_recreate:
            print(f"[setup] removing existing DB directory: {db_dir}")
            shutil.rmtree(db_dir, ignore_errors=True)
        else:
            print(f"[setup] DB already exists: {mv_db}")
            print("  Use --force-recreate to delete and rebuild.")
            return 1

    db_dir.mkdir(parents=True, exist_ok=True)
    sigs_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Create database
    rc = _run([str(ghidra_bsim), "createdatabase", db_url, "medium_nosize"])
    if rc != 0:
        print(f"[error] createdatabase failed (rc={rc})")
        return rc

    # Step 2: Generate signatures for all programs in the project
    rc = _run([
        str(ghidra_bsim), "generatesigs",
        project_url, str(sigs_dir),
        "--bsim", db_url,
    ])
    if rc != 0:
        print(f"[error] generatesigs failed (rc={rc})")
        print("  Note: if URL error, try --force-recreate and check project_url format.")
        print(f"  project_url used: {project_url}")
        return rc

    # Step 3: Commit signatures to database
    rc = _run([str(ghidra_bsim), "commitsigs", db_url, str(sigs_dir)])
    if rc != 0:
        print(f"[error] commitsigs failed (rc={rc})")
        return rc

    print(f"\n[done] DB created: {mv_db}")
    print(f"[done] Sigs at: {sigs_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
