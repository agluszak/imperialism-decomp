#!/usr/bin/env python3
"""Stage 3: push source-owned names into the Ghidra DB so sync converges.

Source method names are canonical (they are what the binary compiles, and the
human's mental model); Ghidra names are provisional (Hard Rule 6). After a
`just sync-ghidra` the export carries Ghidra's names, which `merge_curated_symbols`
then has to re-overwrite by address every time — names churn but never converge.

This tool closes the loop in the other direction: for every address the *source*
owns (`function_ownership.csv` ownership=manual) it writes the canonical source
name into the Ghidra DB's function (creating the `Class::` namespace as needed),
leaving Ghidra-only addresses untouched. The next export then already produces the
matching name, so `sync-ghidra` converges instead of churning.

Canonical names are the *explicitly curated* source names — the manifest
curated.slots (`Class::method`) and config/function_name_overrides.csv (the
latter wins). It deliberately does NOT push the bulk of config/symbols.csv: those
names are mostly just the previous Ghidra export, so pushing them back would be a
no-op at best and a revert of newer DB names at worst. Backtick/synthetic names
(scalar deleting destructors) and non-identifier names are skipped.

Dry-run by default (prints the planned renames); pass --apply to open the project
writable and `program.save()`. Wired into `just sync-ghidra` before export and
runnable standalone as `just push-names`.

Usage:
  uv run python -m tools.ghidra.push_names_to_ghidra [--apply] [--limit N] [--verbose]
"""

from __future__ import annotations

import argparse
import re

import pyghidra

from tools.common import class_manifest, ghidra_env
from tools.common.name_overrides import parse_name_overrides
from tools.common.pipe_csv import normalize_hex, read_pipe_rows
from tools.common.repo import repo_root_from_file

REPO_ROOT = repo_root_from_file(__file__)
OWNERSHIP_PATH = REPO_ROOT / "config" / "function_ownership.csv"
NAME_OVERRIDES_PATH = REPO_ROOT / "config" / "function_name_overrides.csv"

IDENT_RE = re.compile(r"^[A-Za-z_~][A-Za-z0-9_]*$")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Push source-owned names into the Ghidra DB.")
    p.add_argument("--apply", action="store_true", help="Write changes (default: dry-run).")
    p.add_argument("--limit", type=int, default=0, help="Process at most N renames (0 = all).")
    p.add_argument("--verbose", action="store_true", help="Print every planned rename.")
    return p.parse_args()


def owned_addresses() -> set[int]:
    out: set[int] = set()
    for row in read_pipe_rows(OWNERSHIP_PATH):
        if (row.get("ownership") or "").strip() != "manual":
            continue
        addr = normalize_hex((row.get("address") or "").strip())
        if addr:
            out.add(int(addr, 16))
    return out


def canonical_names(owned: set[int]) -> dict[int, str]:
    """address -> explicitly-curated (possibly ``Class::``-qualified) source name.

    Only the curated surfaces are pushed: manifest curated.slots and
    function_name_overrides.csv (the latter wins). The bulk of symbols.csv is NOT
    a curation signal (it is mostly the previous export) and is intentionally
    excluded so a push can never revert a newer Ghidra DB name.
    """
    names: dict[int, str] = {}
    # 1. manifest curated.slots methods (Class::method)
    for cls, manifest in class_manifest.load_all_manifests(REPO_ROOT).items():
        gen = manifest.get("generated") or {}
        target_by_index = {
            class_manifest._as_int(s["index"]): class_manifest._as_int(s["target"])
            for s in (gen.get("slots") or [])
            if "index" in s and s.get("target")
        }
        for rec in (manifest.get("curated") or {}).get("slots") or []:
            method = (rec.get("method") or "").strip()
            if not method or "index" not in rec:
                continue
            target = target_by_index.get(class_manifest._as_int(rec["index"]))
            if target is not None and target in owned:
                names[target] = f"{cls}::{method}"
    # 2. explicit per-address overrides (highest precedence)
    for addr, (name, _proto) in parse_name_overrides(NAME_OVERRIDES_PATH).items():
        if addr in owned and name:
            names[addr] = name
    return names


def split_qualified(qualified: str) -> tuple[list[str], str]:
    parts = qualified.split("::")
    return parts[:-1], parts[-1]


def run(program, args) -> dict:
    from ghidra.program.model.symbol import SourceType

    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    st = program.getSymbolTable()

    def A(x: int):
        return af.getAddress(x)

    def get_namespace(path: list[str]):
        parent = None
        for part in path:
            existing = st.getNamespace(part, parent)
            parent = existing if existing is not None else st.createClass(parent, part, SourceType.USER_DEFINED)
        return parent

    owned = owned_addresses()
    wanted = canonical_names(owned)

    stats = {"planned": 0, "applied": 0, "already": 0, "no_function": 0, "skipped_name": 0}
    changes: list[str] = []

    for addr in sorted(wanted):
        desired_qualified = wanted[addr]
        ns_path, simple = split_qualified(desired_qualified)
        if not IDENT_RE.match(simple):
            stats["skipped_name"] += 1
            continue
        fn = fm.getFunctionAt(A(addr))
        if fn is None:
            stats["no_function"] += 1
            continue
        current = fn.getName(True)
        if current == desired_qualified:
            stats["already"] += 1
            continue
        stats["planned"] += 1
        if args.limit and stats["planned"] > args.limit:
            stats["planned"] -= 1
            break
        if args.verbose or not args.apply:
            changes.append(f"  0x{addr:08x}: {current} -> {desired_qualified}")
        if args.apply:
            try:
                ns = get_namespace(ns_path) if ns_path else None
                if ns is not None:
                    fn.setParentNamespace(ns)
                fn.setName(simple, SourceType.USER_DEFINED)
                stats["applied"] += 1
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! 0x{addr:08x} -> {desired_qualified} failed: {exc}")

    return {"stats": stats, "changes": changes, "owned": len(owned), "wanted": len(wanted)}


def main() -> int:
    args = parse_args()
    project = ghidra_env.open_project()
    consumer = None
    program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        if args.apply:
            txid = program.startTransaction("push source-owned names")
        result = run(program, args)
        if args.apply:
            program.endTransaction(txid, True)
            txid = None
            program.save("push source-owned names", pyghidra.task_monitor())

        s = result["stats"]
        mode = "APPLIED" if args.apply else "DRY RUN"
        for line in result["changes"][:4000]:
            print(line)
        print(
            f"\n[{mode}] owned={result['owned']} with_source_name={result['wanted']} "
            f"planned={s['planned']} applied={s['applied']} already_matching={s['already']} "
            f"no_function={s['no_function']} skipped_name={s['skipped_name']}"
        )
        if not args.apply:
            print("Re-run with --apply to write these names into the Ghidra DB.")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
