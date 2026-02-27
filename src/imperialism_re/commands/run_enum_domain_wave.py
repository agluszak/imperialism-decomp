#!/usr/bin/env python3
"""
Run an enum-domain wave end-to-end:
  1) extract candidates
  2) build enum spec
  3) optionally apply enum/type propagation
  4) verify propagation hotspots
"""

from __future__ import annotations

import argparse
import csv
import importlib
import sys
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root


def _run_module(module_name: str, argv: list[str]) -> None:
    module = importlib.import_module(module_name)
    if not hasattr(module, "main"):
        raise RuntimeError(f"module has no main(): {module_name}")
    old_argv = sys.argv
    sys.argv = [module_name.rsplit(".", 1)[-1] + ".py", *argv]
    try:
        rc = module.main()
    finally:
        sys.argv = old_argv
    if rc not in (None, 0):
        raise RuntimeError(f"{module_name} failed with rc={rc}")


def _csv_rows(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", newline="") as fh:
        return max(0, sum(1 for _ in csv.DictReader(fh)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch-tag", required=True)
    ap.add_argument("--domains-csv", required=True)
    ap.add_argument("--out-dir", default="tmp_decomp")
    ap.add_argument("--addr-min", default="0x00400000")
    ap.add_argument("--addr-max", default="0x006fffff")
    ap.add_argument("--max-functions", type=int, default=0)
    ap.add_argument("--domains", default="", help="Optional comma-separated domain filter")
    ap.add_argument("--min-evidence", type=int, default=3)
    ap.add_argument("--cluster-threshold", type=int, default=1)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--apply-tables", action="store_true")
    ap.add_argument(
        "--skip-create-enums",
        action="store_true",
        help="When applying, skip create_gameplay_enums stage and only propagate types",
    )
    ap.add_argument(
        "--fail-on-hotspots",
        action="store_true",
        help="Return non-zero when post-verify hotspots are present",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)

    domains_csv = Path(args.domains_csv)
    if not domains_csv.is_absolute():
        domains_csv = root / domains_csv
    if not domains_csv.exists():
        print(f"[error] missing domains csv: {domains_csv}")
        return 1

    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    candidates_csv = out_dir / f"{args.batch_tag}_enum_candidates.csv"
    spec_json = out_dir / f"{args.batch_tag}_enum_spec.json"
    hotspots_csv = out_dir / f"{args.batch_tag}_enum_hotspots.csv"

    _run_module(
        "imperialism_re.commands.extract_enum_domain_candidates",
        [
            "--domains-csv",
            str(domains_csv),
            "--out-csv",
            str(candidates_csv),
            "--addr-min",
            str(args.addr_min),
            "--addr-max",
            str(args.addr_max),
            "--max-functions",
            str(args.max_functions),
            "--project-root",
            str(root),
        ],
    )

    _run_module(
        "imperialism_re.commands.build_enum_spec_from_candidates",
        [
            "--in-csv",
            str(candidates_csv),
            "--out-json",
            str(spec_json),
            "--min-evidence",
            str(args.min_evidence),
            "--cluster-threshold",
            str(args.cluster_threshold),
            "--domains",
            str(args.domains),
            "--project-root",
            str(root),
        ],
    )

    if args.apply:
        if not args.skip_create_enums:
            argv = [
                "--spec-json",
                str(spec_json),
                "--project-root",
                str(root),
            ]
            if args.apply_tables:
                argv.append("--apply-tables")
            _run_module("imperialism_re.commands.create_gameplay_enums", argv)

        _run_module(
            "imperialism_re.commands.apply_enum_param_types_clustered",
            [
                "--in-csv",
                str(candidates_csv),
                "--domains",
                str(args.domains),
                "--min-evidence",
                str(args.min_evidence),
                "--cluster-threshold",
                str(args.cluster_threshold),
                "--apply",
                "--project-root",
                str(root),
            ],
        )
        _run_module(
            "imperialism_re.commands.apply_enum_struct_fields_clustered",
            [
                "--in-csv",
                str(candidates_csv),
                "--domains",
                str(args.domains),
                "--min-evidence",
                str(args.min_evidence),
                "--cluster-threshold",
                str(args.cluster_threshold),
                "--apply",
                "--project-root",
                str(root),
            ],
        )

    _run_module(
        "imperialism_re.commands.verify_enum_propagation_hotspots",
        [
            "--in-csv",
            str(candidates_csv),
            "--out-csv",
            str(hotspots_csv),
            "--domains",
            str(args.domains),
            "--min-evidence",
            str(args.min_evidence),
            "--cluster-threshold",
            str(args.cluster_threshold),
            "--project-root",
            str(root),
        ],
    )

    candidates_rows = _csv_rows(candidates_csv)
    hotspots_rows = _csv_rows(hotspots_csv)
    print(f"[done] batch={args.batch_tag}")
    print(f"[artifact] candidates={candidates_csv} rows={candidates_rows}")
    print(f"[artifact] spec={spec_json}")
    print(f"[artifact] hotspots={hotspots_csv} rows={hotspots_rows}")
    if args.fail_on_hotspots and hotspots_rows > 0:
        print(f"[error] hotspots present: {hotspots_rows}")
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
