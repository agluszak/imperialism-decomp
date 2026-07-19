#!/usr/bin/env python3
"""One-way apply: manual C++ source -> the live Ghidra DB.

The single sanctioned mutation path from the source model into Ghidra (the DB is
an analysis workspace and downstream projection; nothing flows back
automatically). It derives everything from the two canonical inputs:

  1. **Source markers** (tools.source_index): every claimed address. For
     `// FUNCTION:` claims the qualified name is parsed from the C++ definition
     that follows the marker; `// SYNTHETIC:`/`// TEMPLATE:`/`// LIBRARY:`
     claims take the name from the convention comment line under the marker.
  2. **The raw inventory** (config/original_entities.csv): fallback advisory
     names for claimed addresses whose declaration could not be parsed, and for
     curated-but-unported rows.

Applied to the DB (dry-run by default; --apply writes and saves):
  - function names + class namespaces (decided against the PRIMARY entity —
    a matching *secondary* label never masks a stale primary);
  - labels for non-function addresses;
  - `Class::'vftable'` labels for every `// VTABLE:` annotation (class name
    parsed from the following `class X` declaration).

After --apply, run `just export-project` so the vendored .gzf carries the
result (`just ghidra-apply-source-full` chains build -> apply -> export).

Known gap (repair tool: `just ghidra-rename-class`): class *datatype* renames
and PDB-driven struct/inheritance import are not yet applied here; the audit at
the end reports class namespaces whose datatype name diverges from source.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pyghidra

from tools.common import ghidra_env
from tools.common.pipe_csv import read_pipe_table
from tools.common.repo import repo_root_from_file
from tools.source_index import MarkerClaim, scan_marker_claims

REPO_ROOT = repo_root_from_file(__file__, levels_up=2)
INVENTORY = REPO_ROOT / "config" / "original_entities.csv"

_VTABLE_RE = re.compile(r"//\s*VTABLE\s*:\s*(\w+)\s+(?:0x)?([0-9a-fA-F]+)", re.IGNORECASE)
_CLASS_DECL_RE = re.compile(r"^\s*(?:class|struct)\s+([A-Za-z_]\w*)")
# Out-of-line definition/declaration head: `Ret Class::Method(...)` or `Ret Name(...)`.
_DEF_RE = re.compile(
    r"^[\w:<>*&~\s]*?\b((?:[A-Za-z_]\w*::)+~?[A-Za-z_]\w*|[A-Za-z_]\w*)\s*\("
)
_NAME_COMMENT_RE = re.compile(r"^//\s*((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*$")


def split_qualified(qualified: str) -> tuple[list[str], str]:
    parts = qualified.split("::")
    return parts[:-1], parts[-1]


def name_from_claim(claim: MarkerClaim, lines: list[str]) -> str | None:
    """Source-derived qualified name for a marker claim, or None if unparsable."""
    idx = claim.line - 1  # 0-based marker line
    if claim.kind == "FUNCTION":
        # The declaration is the next non-empty line (Hard Rule 3).
        for j in range(idx + 1, min(idx + 3, len(lines))):
            line = lines[j].strip()
            if not line:
                continue
            m = _DEF_RE.match(line)
            if m and "::" in m.group(1):
                return m.group(1)
            return None
        return None
    # SYNTHETIC/TEMPLATE/LIBRARY: convention puts the name (or mangled symbol)
    # on the comment line directly under the marker. Only plain qualified
    # identifiers are usable as Ghidra names.
    if idx + 1 < len(lines):
        m = _NAME_COMMENT_RE.match(lines[idx + 1].strip())
        if m:
            return m.group(1)
    return None


def source_names(repo_root: Path, target: str) -> dict[int, str]:
    """addr -> qualified name derived from manual source (markers + decls)."""
    out: dict[int, str] = {}
    cache: dict[str, list[str]] = {}
    for claim in scan_marker_claims(repo_root, target):
        if claim.file not in cache:
            try:
                cache[claim.file] = (repo_root / claim.file).read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
            except OSError:
                cache[claim.file] = []
        name = name_from_claim(claim, cache[claim.file])
        if name:
            out.setdefault(claim.address, name)
    return out


def source_vtables(repo_root: Path, target: str) -> dict[int, str]:
    """vtable addr -> owning class name, from // VTABLE: annotations."""
    from tools.common.file_scan import is_generated_source_path, iter_files

    out: dict[int, str] = {}
    for path in iter_files([str(repo_root / "src"), str(repo_root / "include")]):
        if is_generated_source_path(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            m = _VTABLE_RE.search(line)
            if not m or m.group(1).upper() != target.upper():
                continue
            addr = int(m.group(2), 16)
            # The annotated class declaration follows within a few lines.
            for j in range(i + 1, min(i + 6, len(lines))):
                cm = _CLASS_DECL_RE.match(lines[j])
                if cm:
                    out.setdefault(addr, cm.group(1))
                    break
    return out


def inventory_names() -> dict[int, str]:
    out: dict[int, str] = {}
    if not INVENTORY.is_file():
        return out
    _fields, rows = read_pipe_table(INVENTORY)
    for row in rows:
        name = (row.get("name") or "").strip()
        addr_text = (row.get("address") or "").strip()
        if not name or not addr_text:
            continue
        try:
            out[int(addr_text, 16)] = name
        except ValueError:
            continue
    return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--apply", action="store_true", help="Write and save the DB (default: dry-run).")
    parser.add_argument("--quiet", action="store_true", help="Only print the summary lines.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    derived = source_names(REPO_ROOT, args.target)
    vtables = source_vtables(REPO_ROOT, args.target)
    fallback = inventory_names()
    # Source wins; inventory names fill claimed-or-curated addresses source
    # could not name (unparsable decls, curated-but-unported rows).
    wanted: dict[int, str] = dict(fallback)
    wanted.update(derived)
    print(
        f"source-derived names: {len(derived)}; inventory fallback: {len(fallback)}; "
        f"vtable annotations: {len(vtables)}"
    )

    project = ghidra_env.open_project()
    consumer = program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.exception import DuplicateNameException, InvalidInputException

        af = program.getAddressFactory().getDefaultAddressSpace()
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        global_ns = program.getGlobalNamespace()

        def get_namespace(path: list[str]):
            parent = None
            for part in path:
                existing = st.getNamespace(part, parent)
                parent = existing if existing is not None else st.createClass(
                    parent, part, SourceType.USER_DEFINED
                )
            return parent

        if args.apply:
            txid = program.startTransaction("apply source model")

        stats = {"primary_exact": 0, "fn": 0, "label": 0, "vtable": 0,
                 "skipped_illegal": 0, "failed": 0}

        for addr in sorted(wanted):
            name = wanted[addr]
            if any(ch in name for ch in "` "):
                stats["skipped_illegal"] += 1
                continue
            a = af.getAddress(addr)
            ns_path, simple = split_qualified(name)
            fn = fm.getFunctionAt(a)
            if fn is not None:
                if fn.getName(True) == name:
                    stats["primary_exact"] += 1
                    continue
            else:
                prim = st.getPrimarySymbol(a)
                if prim is not None and prim.getName(True) == name:
                    stats["primary_exact"] += 1
                    continue
            if not args.apply:
                if not args.quiet:
                    print(f"  would set 0x{addr:08x} -> {name} ({'fn' if fn else 'label'})")
                stats["fn" if fn is not None else "label"] += 1
                continue
            try:
                ns = get_namespace(ns_path) if ns_path else global_ns
                if fn is not None:
                    if ns is not None:
                        fn.setParentNamespace(ns)
                    fn.setName(simple, SourceType.USER_DEFINED)
                    stats["fn"] += 1
                else:
                    st.createLabel(a, simple, ns, SourceType.USER_DEFINED).setPrimary()
                    stats["label"] += 1
            except (DuplicateNameException, InvalidInputException) as exc:
                stats["failed"] += 1
                print(f"  !! 0x{addr:08x} -> {name} failed: {exc}")

        # Vtable labels from // VTABLE: annotations.
        for addr, cls in sorted(vtables.items()):
            a = af.getAddress(addr)
            prim = st.getPrimarySymbol(a)
            wanted_label = f"{cls}::'vftable'"
            if prim is not None and prim.getName(True) == wanted_label:
                continue
            if not args.apply:
                if not args.quiet:
                    print(f"  would label vtable 0x{addr:08x} -> {wanted_label}")
                stats["vtable"] += 1
                continue
            try:
                ns = get_namespace([cls])
                st.createLabel(a, "'vftable'", ns, SourceType.USER_DEFINED).setPrimary()
                stats["vtable"] += 1
            except (DuplicateNameException, InvalidInputException) as exc:
                stats["failed"] += 1
                print(f"  !! vtable 0x{addr:08x} -> {wanted_label} failed: {exc}")

        if args.apply:
            program.endTransaction(txid, True)
            txid = None
            program.save("apply source model", pyghidra.task_monitor())

        # Live audit: class namespaces used by source vs DB datatype names.
        source_classes = {c for n in wanted.values() if "::" in n
                          for c in [n.rsplit("::", 1)[0]] if "::" not in c}
        source_classes |= set(vtables.values())
        dt_names = {dt.getName() for dt in dtm.getAllDataTypes()}
        drift = sorted(c for c in source_classes
                       if c not in dt_names and f"{c}Vtbl" in dt_names)
        if drift:
            print(f"audit: {len(drift)} class(es) with a Vtbl datatype but no class "
                  f"datatype under the source name (repair: just ghidra-rename-class):")
            for c in drift[:10]:
                print(f"    - {c}")

        mode = "APPLIED" if args.apply else "DRY RUN"
        print(
            f"[{mode}] primary_exact={stats['primary_exact']} set_fn={stats['fn']} "
            f"set_label={stats['label']} vtable_labels={stats['vtable']} "
            f"skipped_illegal={stats['skipped_illegal']} failed={stats['failed']}"
        )
        if args.apply:
            print("Run `just export-project` so the vendored .gzf carries the result.")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
