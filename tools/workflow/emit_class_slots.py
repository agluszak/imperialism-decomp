#!/usr/bin/env python3
"""Emit virtual declarations and promote slot bodies for recovered classes.

Invoked by ``just recover-class`` (not standalone ``gen-class --write``). Reads
the per-class manifest, gap-fills a ``GENERATED DECLS`` region in the header, and
merges ``// FUNCTION:`` bodies from ``src/ghidra_autogen/`` into the manual
``.cpp`` at ascending address order.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common import class_manifest as cm
from tools.common.pipe_csv import normalize_hex
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.common.thunk_names import ThunkResolver, load_thunk_map
from tools.workflow import class_codegen as bc
from tools.workflow.shape_body import shape_body
from tools.workflow.gen_class import (
    classified_from_manifest,
    header_path,
    manifest_path,
    render_generated_decls,
    upsert_decls_block,
)
from tools.workflow.promote_from_autogen import (
    annotation_re,
    collect_autogen_blocks,
)

_MODULE = "IMPERIALISM"
_GHIDRA_FUNC = re.compile(
    r"^\s*//\s*GHIDRA_FUNCTION\s+IMPERIALISM\s+(?:0x)?([0-9a-fA-F]+)\s*$",
    re.MULTILINE,
)


def _owned_addresses(repo_root: Path) -> dict[int, str]:
    path = resolve_repo_path(repo_root, "config/function_ownership.csv")
    if not path.exists():
        return {}
    out: dict[int, str] = {}
    from tools.common.pipe_csv import read_pipe_rows

    for row in read_pipe_rows(path):
        if (row.get("ownership") or "").strip() != "manual":
            continue
        addr = normalize_hex((row.get("address") or "").strip())
        if addr:
            out[int(addr, 16)] = (row.get("target_cpp") or "").strip()
    return out


def _emit_slots(slots: list[bc.ClassifiedSlot]) -> list[bc.ClassifiedSlot]:
    """Slots that need header declarations (exclude null/ilt_thunk only)."""
    return [s for s in slots if s.kind not in ("null", "ilt_thunk")]


def _body_slots(
    slots: list[bc.ClassifiedSlot], owned: dict[int, str], target_cpp_rel: str
) -> list[bc.ClassifiedSlot]:
    """Slots needing a body claim in this class's .cpp."""
    out: list[bc.ClassifiedSlot] = []
    for s in slots:
        if s.kind not in ("override", "new", "scalar_dtor"):
            continue
        addr = int(s.target_addr or "0", 16)
        existing = owned.get(addr)
        if existing and existing != target_cpp_rel:
            continue
        out.append(s)
    return out


def autogen_to_manual_block(block: str, addr: int) -> str:
    """Convert a ghidra_autogen block into a manual // FUNCTION: seed."""
    lines = block.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _GHIDRA_FUNC.match(line)
        if m:
            out.append(f"// FUNCTION: IMPERIALISM 0x{addr:08x}")
            i += 1
            while i < len(lines) and lines[i].startswith("// GHIDRA_"):
                i += 1
            continue
        if line.startswith("// GHIDRA_FUNCTION"):
            out.append(f"// FUNCTION: IMPERIALISM 0x{addr:08x}")
            i += 1
            while i < len(lines) and lines[i].startswith("// GHIDRA_"):
                i += 1
            continue
        out.append(line)
        i += 1
    return "\n".join(out).rstrip() + "\n"


def _is_scaffold_stub(block: str) -> bool:
    """True if a block is a gen-class scaffold stub safe to replace with a real body.

    gen-class scaffolds every new/override slot with a ``// FUNCTION:`` placeholder
    carrying this marker. emit-class-slots replaces those with the shaped autogen
    body; any other existing block (a human-edited body, a real port) is left alone.
    """
    return "TODO(manifest): port the body from Ghidra" in block


def scalar_dtor_block(cls: str, addr: int) -> str:
    return (
        f"// SYNTHETIC: IMPERIALISM 0x{addr:08x}\n"
        f"// {cls}::`scalar deleting destructor'\n"
    )


def merge_cpp_bodies(
    cpp_text: str,
    cls: str,
    body_slots: list[bc.ClassifiedSlot],
    autogen: dict[int, str],
    resolver: ThunkResolver | None = None,
) -> tuple[str, list[int], list[int]]:
    """Insert promoted/SYNTHETIC blocks at ascending address order. Returns (text, promoted, missing)."""
    addr_marker = re.compile(
        r"^\s*//\s*(?:"
        r"(?:FUNCTION|STUB)\s*:\s*IMPERIALISM\s+"
        r"|SYNTHETIC:\s*IMPERIALISM\s+"
        r"|GHIDRA_FUNCTION\s+IMPERIALISM\s+"
        r")(?:0x)?([0-9a-fA-F]+)\s*$",
        re.MULTILINE,
    )
    matches = list(addr_marker.finditer(cpp_text))
    preamble = cpp_text[: matches[0].start()] if matches else cpp_text
    existing: dict[int, str] = {}
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(cpp_text)
        addr = int(match.group(1), 16)
        existing[addr] = cpp_text[start:end].rstrip() + "\n\n"

    promoted: list[int] = []
    missing: list[int] = []
    for s in sorted(body_slots, key=lambda x: int(x.target_addr or "0", 16)):
        addr = int(s.target_addr or "0", 16)
        is_stub = addr in existing and _is_scaffold_stub(existing[addr])
        if addr in existing and not is_stub:
            continue  # human-owned or already a real body — never clobber
        if s.kind == "scalar_dtor":
            # scalar dtors stay SYNTHETIC (Hard Rule 9); only seed when absent.
            if addr not in existing:
                existing[addr] = scalar_dtor_block(cls, addr)
                promoted.append(addr)
            continue
        if addr not in autogen:
            if not is_stub:
                missing.append(addr)
            continue  # keep the scaffold stub when there is no autogen to shape
        existing[addr] = shape_body(autogen[addr], s, cls, resolver) + "\n"
        promoted.append(addr)

    if not existing:
        body = ""
    else:
        body = "".join(existing[a] for a in sorted(existing))
    if preamble and not preamble.endswith("\n"):
        preamble += "\n"
    return preamble.rstrip() + "\n\n" + body, promoted, missing


def emit_class_slots(repo_root: Path, cls: str, write: bool) -> int:
    mpath = manifest_path(repo_root, cls)
    if not mpath.exists():
        print(f"emit-class-slots: no manifest {mpath}")
        return 1
    manifest = cm.load_manifest(mpath)
    hpath = header_path(repo_root, cls)
    if not hpath.exists():
        print(f"emit-class-slots {cls}: no header at {hpath} (use gen-class scaffold for new classes)")
        return 1

    cpp_path = resolve_repo_path(repo_root, f"src/game/{cls}.cpp")
    target_cpp_rel = f"src/game/{cls}.cpp"
    slots = classified_from_manifest(manifest, repo_root)
    decl_slots = _emit_slots(slots)
    owned = _owned_addresses(repo_root)
    body_slots = _body_slots(slots, owned, target_cpp_rel)

    decls_block = render_generated_decls(manifest, decl_slots)
    header_text = hpath.read_text(encoding="utf-8")
    new_header, header_changed = upsert_decls_block(header_text, cls, decls_block)

    autogen_dir = resolve_repo_path(repo_root, "src/ghidra_autogen")
    autogen = collect_autogen_blocks(autogen_dir, _MODULE) if autogen_dir.is_dir() else {}

    resolver = ThunkResolver(load_thunk_map(resolve_repo_path(repo_root, "config/thunk_map.csv")))

    cpp_text = cpp_path.read_text(encoding="utf-8") if cpp_path.exists() else ""
    new_cpp, promoted, missing = merge_cpp_bodies(cpp_text, cls, body_slots, autogen, resolver)
    cpp_changed = new_cpp != cpp_text

    sym_plan = bc.plan_symbols(
        resolve_repo_path(repo_root, "config/symbols.csv"),
        body_slots,
        cls,
    )
    own_plan = bc.plan_ownership(
        resolve_repo_path(repo_root, "config/function_ownership.csv"),
        [s for s in body_slots if s.kind != "scalar_dtor"],
        target_cpp_rel,
    )

    print(f"emit-class-slots {cls}:")
    print(f"  decl slots: {len(decl_slots)}  body slots: {len(body_slots)}")
    print(f"  header {'changed' if header_changed else 'up to date'}")
    print(f"  cpp {'changed' if cpp_changed else 'up to date'}  promoted: {len(promoted)}")
    if promoted:
        print("  promoted addresses: " + ", ".join(f"0x{a:08x}" for a in promoted))
    if missing:
        print("  missing autogen: " + ", ".join(f"0x{a:08x}" for a in missing))
    if own_plan.collisions:
        print("  ownership collisions:")
        for c in own_plan.collisions:
            print(f"    {c}")

    if not write:
        if header_changed:
            print("\n--- new GENERATED DECLS ---")
            print(decls_block)
        if cpp_changed and promoted:
            print("\n--- cpp would gain blocks at ---")
            for a in promoted:
                print(f"  0x{a:08x}")
        print("Pass --write to apply.")
        return 1 if own_plan.collisions else 0

    if own_plan.collisions:
        print("emit-class-slots: refusing --write due to ownership collisions.")
        return 1

    if header_changed:
        hpath.write_text(new_header, encoding="utf-8")
    if cpp_changed:
        cpp_path.parent.mkdir(parents=True, exist_ok=True)
        cpp_path.write_text(new_cpp, encoding="utf-8")
    if sym_plan.new_rows or sym_plan.updated_rows:
        sym_plan.path.write_text(sym_plan.merged_text())
    if own_plan.new_rows:
        own_plan.path.write_text(own_plan.merged_text())

    print(f"emit-class-slots {cls}: applied to {hpath.name} + {cpp_path.name}.")
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Emit virtual decls + promote slot bodies for a class.")
    p.add_argument("cls", help="Class name (config/classes/<Class>.yml).")
    p.add_argument("--write", action="store_true", help="Apply changes (default: dry-run).")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    return emit_class_slots(repo_root_from_file(__file__), args.cls, args.write)


if __name__ == "__main__":
    raise SystemExit(main())
