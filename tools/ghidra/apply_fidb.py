#!/usr/bin/env python3
"""Attach/query/apply a Ghidra Function ID database through pyghidra.

Dry-run mode attaches the FIDB in the current pyghidra JVM, queries Function ID
matches, and optionally writes a CSV report. ``--apply`` runs Ghidra's own
``ApplyFidEntriesCommand`` against the executable address set and saves the live
project.

Usage:
  uv run python -m tools.ghidra.apply_fidb
  uv run python -m tools.ghidra.apply_fidb --out tmp_decomp/msvc500_fid_matches.csv
  uv run python -m tools.ghidra.apply_fidb --apply
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import pyghidra

from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file, resolve_repo_path

DEFAULT_FIDB = "vendor/msvc500/fid-generation/fidb/msvc500.fidb"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Attach/query/apply a Ghidra FIDB.")
    p.add_argument(
        "--fidb",
        default=DEFAULT_FIDB,
        help=f"FIDB path, repo-relative or absolute (default: {DEFAULT_FIDB}).",
    )
    p.add_argument(
        "--out",
        default="tmp_decomp/msvc500_fid_matches.csv",
        help="Dry-run CSV output path (default: tmp_decomp/msvc500_fid_matches.csv).",
    )
    p.add_argument("--apply", action="store_true", help="Apply FID labels/bookmarks to the Ghidra DB.")
    p.add_argument(
        "--force-primary-names",
        action="store_true",
        help="With --apply, replace primary function names with best FID match names.",
    )
    p.add_argument(
        "--include-existing-fidbs",
        action="store_true",
        help="Also query/apply currently-active Ghidra FIDBs. Default is generated FIDB only.",
    )
    p.add_argument(
        "--always-apply-labels",
        action="store_true",
        help="Let FID add labels even when user/imported labels already exist.",
    )
    p.add_argument(
        "--no-bookmarks",
        action="store_true",
        help="Do not create Function ID analysis bookmarks during --apply.",
    )
    p.add_argument(
        "--score-threshold",
        type=float,
        default=None,
        help="FID primary score threshold (default: Ghidra FidService default).",
    )
    p.add_argument(
        "--multi-name-threshold",
        type=float,
        default=None,
        help="FID multi-name score threshold for --apply (default: Ghidra FidService default).",
    )
    p.add_argument(
        "--sample",
        type=int,
        default=40,
        help="Number of dry-run sample matches to print (default: 40).",
    )
    return p.parse_args()


def _attach_fidb(fidb_path: Path):
    from java.io import File as JavaFile

    from ghidra.feature.fid.db import FidFileManager

    fidb = JavaFile(str(fidb_path))
    fid_file = FidFileManager.getInstance().addUserFidFile(fidb)
    if fid_file is None:
        raise RuntimeError(f"Could not attach FIDB: {fidb_path}")
    fid_file.setActive(True)
    return fid_file


def _set_exclusive_fidb(target_fid_file):
    from ghidra.feature.fid.db import FidFileManager

    manager = FidFileManager.getInstance()
    previous = []
    files = manager.getFidFiles()
    it = files.iterator()
    while it.hasNext():
        fid_file = it.next()
        previous.append((fid_file, bool(fid_file.isActive())))
        fid_file.setActive(fid_file == target_fid_file)
    return previous


def _restore_fidb_activity(previous) -> None:
    for fid_file, was_active in previous:
        fid_file.setActive(was_active)


def _fid_service_defaults():
    from ghidra.feature.fid.service import FidService

    service = FidService()
    return service, float(service.getDefaultScoreThreshold()), float(service.getDefaultMultiNameThreshold())


def _best_match(result):
    matches = result.matches
    if matches is None or matches.isEmpty():
        return None
    best = None
    best_score = -1.0
    it = matches.iterator()
    while it.hasNext():
        match = it.next()
        score = float(match.getOverallScore())
        if best is None or score > best_score:
            best = match
            best_score = score
    return best


def _match_row(result, match) -> dict[str, str]:
    fn = result.function
    function_record = match.getFunctionRecord()
    library = match.getLibraryRecord()
    return {
        "address": f"0x{int(fn.getEntryPoint().getOffset()):08x}",
        "current_name": str(fn.getName()),
        "matched_name": str(function_record.getName()),
        "domain_path": str(function_record.getDomainPath()),
        "library_family": str(library.getLibraryFamilyName()),
        "library_version": str(library.getLibraryVersion()),
        "library_variant": str(library.getLibraryVariant()),
        "overall_score": f"{float(match.getOverallScore()):.3f}",
        "primary_score": f"{float(match.getPrimaryFunctionCodeUnitScore()):.3f}",
        "child_score": f"{float(match.getChildFunctionCodeUnitScore()):.3f}",
        "parent_score": f"{float(match.getParentFunctionCodeUnitScore()):.3f}",
        "match_count": str(result.matches.size()),
    }


def query_matches(program, score_threshold: float) -> list[dict[str, str]]:
    from ghidra.feature.fid.db import FidFileManager

    service, _, _ = _fid_service_defaults()
    query = FidFileManager.getInstance().openFidQueryService(program.getLanguage(), False)
    try:
        results = service.processProgram(program, query, score_threshold, pyghidra.task_monitor())
        rows: list[dict[str, str]] = []
        it = results.iterator()
        while it.hasNext():
            result = it.next()
            if result.function is None or result.function.isThunk() or result.matches is None:
                continue
            match = _best_match(result)
            if match is None:
                continue
            rows.append(_match_row(result, match))
        rows.sort(key=lambda r: int(r["address"], 16))
        return rows
    finally:
        query.close()


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fd:
        writer = csv.DictWriter(fd, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def force_primary_names(program, score_threshold: float) -> dict[str, object]:
    from ghidra.feature.fid.db import FidFileManager
    from ghidra.feature.fid.service import FidService
    from ghidra.program.model.symbol import SourceType, SymbolUtilities
    from ghidra.util.exception import DuplicateNameException, InvalidInputException

    service = FidService()
    query = FidFileManager.getInstance().openFidQueryService(program.getLanguage(), False)
    rows: list[dict[str, str]] = []
    renamed = duplicate_suffixed = failed = 0
    failures: list[str] = []
    try:
        results = service.processProgram(program, query, score_threshold, pyghidra.task_monitor())
        it = results.iterator()
        while it.hasNext():
            result = it.next()
            fn = result.function
            if fn is None or fn.isThunk() or result.matches is None:
                continue
            match = _best_match(result)
            if match is None:
                continue
            row = _match_row(result, match)
            rows.append(row)
            target_name = row["matched_name"]
            old_name = str(fn.getName())
            if old_name == target_name:
                continue
            try:
                fn.setName(target_name, SourceType.USER_DEFINED)
                renamed += 1
                continue
            except DuplicateNameException:
                fallback = str(SymbolUtilities.getAddressAppendedName(target_name, fn.getEntryPoint()))
                try:
                    fn.setName(fallback, SourceType.USER_DEFINED)
                    row["matched_name"] = fallback
                    renamed += 1
                    duplicate_suffixed += 1
                    continue
                except (DuplicateNameException, InvalidInputException) as ex:
                    failed += 1
                    failures.append(f"{row['address']} {old_name} -> {target_name}: {ex}")
            except InvalidInputException as ex:
                failed += 1
                failures.append(f"{row['address']} {old_name} -> {target_name}: {ex}")
        rows.sort(key=lambda r: int(r["address"], 16))
        return {
            "rows": rows,
            "renamed": renamed,
            "duplicate_suffixed": duplicate_suffixed,
            "failed": failed,
            "failures": failures,
        }
    finally:
        query.close()


def apply_fid(program, score_threshold: float, multi_name_threshold: float, args: argparse.Namespace) -> bool:
    from ghidra.feature.fid.cmd import ApplyFidEntriesCommand

    address_set = program.getMemory().getExecuteSet()
    if address_set.isEmpty():
        address_set = program.getMemory().getLoadedAndInitializedAddressSet()
    cmd = ApplyFidEntriesCommand(
        address_set,
        score_threshold,
        multi_name_threshold,
        bool(args.always_apply_labels),
        not bool(args.no_bookmarks),
    )
    ok = bool(cmd.applyTo(program, pyghidra.task_monitor()))
    print(f"apply_fidb: apply_ok={ok} affected_locations={cmd.getFIDLocations().getNumAddresses()}")
    return ok


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    fidb_path = resolve_repo_path(repo_root, args.fidb)
    out_path = resolve_repo_path(repo_root, args.out)
    if not fidb_path.is_file():
        raise FileNotFoundError(fidb_path)

    project = ghidra_env.open_project()
    consumer = None
    program = None
    txid = None
    fid_activity = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        fid_file = _attach_fidb(fidb_path)
        if not args.include_existing_fidbs:
            fid_activity = _set_exclusive_fidb(fid_file)
        _, default_score, default_multi = _fid_service_defaults()
        score_threshold = default_score if args.score_threshold is None else args.score_threshold
        multi_name_threshold = default_multi if args.multi_name_threshold is None else args.multi_name_threshold

        if args.apply:
            txid = program.startTransaction(f"apply FIDB {fidb_path.name}")
            if args.force_primary_names:
                result = force_primary_names(program, score_threshold)
                rows = result["rows"]
                write_csv(out_path, rows)
                print(
                    "apply_fidb force-primary: "
                    f"matches={len(rows)} renamed={result['renamed']} "
                    f"duplicate_suffixed={result['duplicate_suffixed']} failed={result['failed']} "
                    f"out={out_path}"
                )
                for failure in result["failures"][:50]:
                    print(f"  FAILED {failure}")
                ok = result["failed"] == 0
            else:
                ok = apply_fid(program, score_threshold, multi_name_threshold, args)
            program.endTransaction(txid, ok)
            txid = None
            if ok:
                program.save(f"apply FIDB {fidb_path.name}", pyghidra.task_monitor())
            return 0 if ok else 1

        rows = query_matches(program, score_threshold)
        write_csv(out_path, rows)
        print(f"apply_fidb dry-run: fidb={fidb_path}")
        print(f"matches={len(rows)} out={out_path}")
        for row in rows[: max(0, args.sample)]:
            print(
                f"{row['address']} {row['current_name']} -> {row['matched_name']} "
                f"[{row['library_family']}:{row['library_version']}:{row['library_variant']} "
                f"score={row['overall_score']}]"
            )
        if rows and args.sample < len(rows):
            print(f"... {len(rows) - args.sample} more rows in {out_path}")
        print("Re-run with --apply to commit FID labels/bookmarks, then `just sync-ghidra` to export.")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if fid_activity is not None:
            _restore_fidb_activity(fid_activity)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
