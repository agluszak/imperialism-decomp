#!/usr/bin/env python3
"""Idempotent class generator driven by a per-class manifest.

`just gen-class <Class>` reads ``config/classes/<Class>.yml`` and maintains a
single *marked* region inside ``include/game/<Class>.h``:

    // === BEGIN GENERATED (TCity) — refreshed by `just gen-class TCity`; do not hand-edit ===
    // vtable @ 0x0064f580 (33 slots), object size 0x2d4, base TObject
    //   slot 0x1d  byte 0x74  0x004b44d0  new       GetCitySummaryRecordSlot74
    //   ...
    // === END GENERATED (TCity) ===

Two modes (mirroring the established generate-then-gate pattern):

  * **Existing/recovered header** (e.g. TCity): *verify + gap-fill only*. The
    generated block is inserted/refreshed in place; the hand-owned class decls,
    doc comments and member annotations outside the block are never touched, and
    bodies in the ``.cpp`` are left byte-for-byte intact. Re-running on an
    unchanged class is a no-op diff.
  * **New class** (no header yet): emit a first-pass ``class_codegen`` skeleton
    from the manifest (header + ``// FUNCTION:`` stubs) *and* the marked block.

The block deliberately carries **no** ``// VTABLE:`` marker (that lives, exactly
once, immediately above the hand-owned class, as the VTABLE-annotation gate
requires) and only an *informational, commented-out* ``static_assert`` on the RTTI
object size by default — an active assert is emitted only when the manifest's
``curated.layout.size_verified`` is true, so generation can never break the build.

``tools.workflow.check_manifest_consistency`` (``just manifest-gate``) re-renders
the block and fails on any drift, so the header and manifest cannot diverge.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from tools.common import class_manifest as cm
from tools.common.file_scan import iter_files
from tools.common.pipe_csv import normalize_hex, read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.common.source_base_slots import (
    SOURCE_BASE_SLOTS,
    apply_source_base_slots,
    source_base_scaffold_issues as _source_base_scaffold_issues,
    source_base_slot_records,
)
from tools.workflow.class_codegen import (
    ClassifiedSlot,
    Signature,
    looks_like_deleting_dtor,
    norm_addr,
    parse_prototype,
    unqualified,
)

# Ghidra names that signal a slot still needs a human semantic name. RTTI getters
# (ClassNamePointer) and scalar deleting destructors are structural machinery, not
# semantic-naming targets, so they are deliberately excluded.
_JUNK_NAME = re.compile(
    r"(FUN_|SUB_|LAB_|Orphan|WrapperFor_|NoOp|_At[0-9A-Fa-f]{6}|VTableSlot|Unknown|Dummy)"
)
_VTABLE_MARKER = re.compile(r"//\s*VTABLE:\s*IMPERIALISM\s+(0x[0-9a-fA-F]+|[0-9a-fA-F]+)")
_CLASS_DECL = re.compile(r"\b(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\b")

BLOCK_BEGIN = "// === BEGIN GENERATED ({cls}) — refreshed by `just gen-class {cls}`; do not hand-edit ==="
BLOCK_END = "// === END GENERATED ({cls}) ==="

DECLS_BEGIN = "// === BEGIN GENERATED DECLS ({cls}) — refreshed by recover-class; do not hand-edit ==="
DECLS_END = "// === END GENERATED DECLS ({cls}) ==="


def manifest_path(repo_root: Path, cls: str) -> Path:
    return resolve_repo_path(repo_root, f"config/classes/{cls}.yml")


def header_path(repo_root: Path, cls: str) -> Path:
    return resolve_repo_path(repo_root, f"include/game/{cls}.h")


# --------------------------------------------------------------------------- #
# Block rendering (shared with the gate)
# --------------------------------------------------------------------------- #


def _slot_display(slot: dict[str, Any], curated: dict[int, dict[str, Any]]) -> str:
    """Human label for a slot: curated method wins, else the Ghidra simple name."""
    idx = int(str(slot["index"]), 16) if isinstance(slot["index"], str) else int(slot["index"])
    cur = curated.get(idx)
    if cur and cur.get("method"):
        return str(cur["method"])
    kind = slot.get("kind")
    if kind == "null":
        return "(null)"
    if kind == "scalar_dtor":
        return "(scalar deleting destructor)"
    if kind == "ilt_thunk":
        return "(ILT thunk — reccmp auto-resolves)"
    name = slot.get("ghidra_name")
    return unqualified(name) if name else "?"


def render_generated_block(manifest: dict[str, Any]) -> str:
    """Render the marked GENERATED block text (BEGIN…END inclusive, no trailing newline)."""
    cls = manifest["class"]
    gen = manifest.get("generated") or {}
    curated = cm.curated_slot_methods(manifest)
    slots = gen.get("slots") or []
    vtable_addr = gen.get("vtable_addr", "0x00000000")
    object_size = gen.get("object_size", "0x0")
    base = gen.get("base") or "<root>"

    # `clang-format off/on` keeps the block byte-stable regardless of line length
    # (long Ghidra names, the aligned slot table) so it always matches a fresh
    # render — otherwise comment reflow at the 100-col limit would fight the gate.
    lines = [BLOCK_BEGIN.format(cls=cls), "// clang-format off"]
    lines.append(
        f"// vtable @ {vtable_addr} ({len(slots)} slots), object size {object_size}, base {base}"
    )
    for slot in slots:
        idx = slot.get("index")
        byte = slot.get("byte")
        target = slot.get("target")
        kind = (slot.get("kind") or "").ljust(9)
        label = _slot_display(slot, curated)
        lines.append(f"//   slot {idx}  byte {byte}  {target}  {kind} {label}")

    size_verified = bool((manifest.get("curated") or {}).get("layout", {}).get("size_verified"))
    if size_verified:
        lines.append(f'static_assert(sizeof({cls}) == {object_size}, "RTTI m_nObjectSize");')
    else:
        lines.append(
            f"// object size {object_size} (RTTI) unverified against the header layout;"
        )
        lines.append("// set curated.layout.size_verified to emit a sizeof static_assert.")
    lines.append("// clang-format on")
    lines.append(BLOCK_END.format(cls=cls))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Block upsert
# --------------------------------------------------------------------------- #


def find_block(text: str, cls: str) -> tuple[int, int] | None:
    """Return (start_line, end_line) indices (inclusive) of the block, or None."""
    begin = BLOCK_BEGIN.format(cls=cls)
    end = BLOCK_END.format(cls=cls)
    lines = text.splitlines()
    start = end_idx = None
    for i, line in enumerate(lines):
        if line.rstrip() == begin:
            start = i
        elif line.rstrip() == end:
            end_idx = i
            break
    if start is None or end_idx is None or end_idx < start:
        return None
    return start, end_idx


def upsert_block(text: str, cls: str, block: str) -> tuple[str, bool]:
    """Replace the existing marked block, or append it at EOF. Returns (text, changed)."""
    lines = text.splitlines()
    found = find_block(text, cls)
    block_lines = block.split("\n")
    if found is not None:
        start, end_idx = found
        if lines[start : end_idx + 1] == block_lines:
            return text, False
        new_lines = lines[:start] + block_lines + lines[end_idx + 1 :]
    else:
        # Append at EOF, separated by one blank line.
        new_lines = lines[:]
        if new_lines and new_lines[-1].strip() != "":
            new_lines.append("")
        new_lines += block_lines
    return "\n".join(new_lines) + "\n", True


# --------------------------------------------------------------------------- #
# Manifest -> ClassifiedSlot (for new-class scaffolding + TODO)
# --------------------------------------------------------------------------- #


def classified_from_manifest(
    manifest: dict[str, Any], repo_root: Path | None = None
) -> list[ClassifiedSlot]:
    """Rebuild class_codegen.ClassifiedSlot records from the manifest.

    Reuses the manifest's already-computed ``kind`` and the curated method name
    (curated wins over the Ghidra name) so the header/cpp scaffolding renders
    from the same slot model as the manifest dump.

    When ``repo_root`` is given, inherited/override slots that lack a local curated
    name additionally adopt the method name (and, for overrides, signature) of the
    same slot in the nearest ancestor manifest, so a derived declaration matches the
    parent virtual it overrides. Without ``repo_root`` only the hardcoded
    TObject/CObject prefix is resolved (``apply_source_base_slots``).
    """
    curated = cm.curated_slot_methods(manifest)
    out: list[ClassifiedSlot] = []
    for s in (manifest.get("generated") or {}).get("slots") or []:
        idx = cm._as_int(s["index"])
        target = norm_addr(str(s.get("target") or "0x0"))
        kind = s.get("kind") or "new"
        cur = curated.get(idx)
        qualified = (cur or {}).get("method") or s.get("ghidra_name")
        proto = s.get("prototype")
        preferred = unqualified(qualified) if qualified else f"VTableSlot{idx:02X}"
        sig: Signature | None = None
        if kind in ("override", "new"):
            parsed = parse_prototype(proto, preferred)
            # The curated/preferred name wins over the prototype's name (which is a
            # provisional Ghidra name); the prototype still supplies ret/args/const.
            sig = Signature(ret=parsed.ret, name=preferred, args=parsed.args, const=parsed.const)
        out.append(
            ClassifiedSlot(
                index=idx,
                byte_offset=cm._as_int(s.get("byte") or 0),
                slot_label=f"0x{idx:02x}",
                target_addr=target,
                kind=kind,
                sig=sig,
                qualified_name=qualified,
                size=int(s.get("size") or 0),
                prototype=proto,
                decompiled_c=None,
                base_target=None,
                dtor_suspect=kind in ("override", "new") and looks_like_deleting_dtor(qualified),
            )
        )
    base = (manifest.get("generated") or {}).get("base") or ""
    out = apply_source_base_slots(out, str(base))
    if repo_root is not None:
        out = apply_ancestry_slots(out, manifest, repo_root)
    return out


def _ancestor_slot_names(
    manifest: dict[str, Any], repo_root: Path
) -> tuple[dict[int, str], dict[int, Signature]]:
    """Per-slot ``(qualified_name, signature)`` from the class's ancestor manifests.

    Walks ``generated.ancestry`` nearest-first; for each slot index records the
    first ancestor that supplies a name, and the first that supplies a signature
    (an ``inherited`` ancestor slot carries a name but no signature, so the two can
    come from different ancestors). Recurses through ``classified_from_manifest`` so
    each ancestor is itself resolved against *its* bases.
    """
    cls = manifest.get("class")
    ancestry = [str(a) for a in (manifest.get("generated") or {}).get("ancestry") or []]
    names: dict[int, str] = {}
    sigs: dict[int, Signature] = {}
    for anc in ancestry[1:]:  # ancestry[0] is the class itself
        if anc == cls:
            continue
        if anc in SOURCE_BASE_SLOTS:
            # Source-owned root (TObject/CObject): use the authoritative prefix
            # table, not the root's own uncurated manifest (whose Ghidra names are
            # the stale cross-class labels source_base_slots exists to correct).
            anc_slots = source_base_slot_records(anc)
        else:
            path = manifest_path(repo_root, anc)
            if not path.exists():
                continue
            anc_slots = classified_from_manifest(cm.load_manifest(path), repo_root)
        for s in anc_slots:
            if s.qualified_name and s.index not in names:
                names[s.index] = s.qualified_name
            if s.sig is not None and s.index not in sigs:
                sigs[s.index] = s.sig
    return names, sigs


def apply_ancestry_slots(
    slots: list[ClassifiedSlot], manifest: dict[str, Any], repo_root: Path
) -> list[ClassifiedSlot]:
    """Adopt parent slot names/signatures for un-curated inherited/override slots."""
    names, sigs = _ancestor_slot_names(manifest, repo_root)
    if not names:
        return slots
    local_curated = set(cm.curated_slot_methods(manifest).keys())

    out: list[ClassifiedSlot] = []
    for slot in slots:
        parent_name = names.get(slot.index)
        if (
            slot.index in local_curated
            or slot.kind not in ("override", "inherited")
            or not parent_name
        ):
            out.append(slot)
            continue
        name = unqualified(parent_name)
        if slot.kind == "inherited":
            # Inherited: only correct the name shown in the slot comment.
            out.append(replace(slot, qualified_name=parent_name))
            continue
        # Override: the C++ signature must match the parent virtual exactly. Prefer
        # the parent's signature; fall back to the derived prototype with the name
        # corrected so it still overrides.
        parent_sig = sigs.get(slot.index)
        if parent_sig is not None:
            new_sig = replace(parent_sig, name=name)
        elif slot.sig is not None:
            new_sig = replace(slot.sig, name=name)
        else:
            new_sig = slot.sig
        out.append(replace(slot, sig=new_sig, qualified_name=parent_name))
    return out


def source_base_scaffold_issues(cls: str, manifest: dict[str, Any]) -> list[str]:
    gen = manifest.get("generated") or {}
    base = str(gen.get("base") or "")
    slots = gen.get("slots") or []
    if not base or not slots:
        return []
    indices = [cm._as_int(s.get("index") or 0) for s in slots]
    return _source_base_scaffold_issues(cls, base, indices)


def render_generated_decls(manifest: dict[str, Any], slots: list[ClassifiedSlot]) -> str:
    """Render the marked GENERATED DECLS block for virtual declarations."""
    cls = manifest["class"]
    lines = [DECLS_BEGIN.format(cls=cls)]
    for s in slots:
        if s.kind == "inherited":
            nm = unqualified(s.qualified_name) if s.qualified_name else "?"
            lines.append(
                f"  // slot {s.slot_label} {nm} inherited unchanged (0x{s.target_addr})"
            )
        elif s.kind == "null":
            lines.append(f"  // slot {s.slot_label} (null in original table)")
        elif s.kind == "ilt_thunk":
            nm = unqualified(s.qualified_name) if s.qualified_name else "?"
            lines.append(
                f"  // slot {s.slot_label} {nm} -> ILT/linker thunk (0x{s.target_addr}); "
                "reccmp auto-resolves, not owned here"
            )
        elif s.kind == "scalar_dtor":
            lines.append(
                f"  virtual ~{cls}(); // slot 0x{s.index:02x} (scalar deleting destructor)"
            )
        elif s.kind in ("override", "new"):
            assert s.sig is not None
            virtual = True
            lines.append(
                f"  {s.sig.decl(virtual=virtual, override=True)} // slot 0x{s.index:02x} 0x{s.target_addr}"
            )
    lines.append(DECLS_END.format(cls=cls))
    return "\n".join(lines)


def find_decls_block(text: str, cls: str) -> tuple[int, int] | None:
    begin = DECLS_BEGIN.format(cls=cls)
    end = DECLS_END.format(cls=cls)
    lines = text.splitlines()
    start = end_idx = None
    for i, line in enumerate(lines):
        if line.rstrip() == begin:
            start = i
        elif line.rstrip() == end:
            end_idx = i
            break
    if start is None or end_idx is None or end_idx < start:
        return None
    return start, end_idx


def upsert_decls_block(text: str, cls: str, block: str) -> tuple[str, bool]:
    """Insert/replace GENERATED DECLS inside the class body (after ``public:``)."""
    lines = text.splitlines()
    block_lines = block.split("\n")
    found = find_decls_block(text, cls)
    if found is not None:
        start, end_idx = found
        if lines[start : end_idx + 1] == block_lines:
            return text, False
        new_lines = lines[:start] + block_lines + lines[end_idx + 1 :]
        return "\n".join(new_lines) + "\n", True

    # Insert after the first ``public:`` following the class declaration.
    class_pat = re.compile(rf"\bclass\s+{re.escape(cls)}\b")
    insert_at = None
    for i, line in enumerate(lines):
        if class_pat.search(line) is None:
            continue
        for j in range(i, min(i + 40, len(lines))):
            if lines[j].strip() == "public:":
                insert_at = j + 1
                break
        if insert_at is not None:
            break
    if insert_at is None:
        raise ValueError(f"{cls}: could not locate class public: section for GENERATED DECLS")

    new_lines = lines[:insert_at] + block_lines + lines[insert_at:]
    return "\n".join(new_lines) + "\n", True


def existing_vtable_annotation(repo_root: Path, cls: str, vtable_addr: str) -> str | None:
    target = norm_addr(vtable_addr)
    if not target:
        return None
    include_root = resolve_repo_path(repo_root, "include/game")
    if not include_root.exists():
        return None
    expected = header_path(repo_root, cls)
    for path in iter_files([str(include_root)], patterns=("*.h", "*.hpp")):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        for i, line in enumerate(lines):
            m = _VTABLE_MARKER.search(line)
            if not m or norm_addr(m.group(1)) != target:
                continue
            if path == expected:
                continue
            owner = path.stem
            for lookahead in lines[i + 1 : i + 8]:
                cmatch = _CLASS_DECL.search(lookahead)
                if cmatch:
                    owner = cmatch.group(1)
                    break
            rel = path.relative_to(repo_root)
            return f"0x{target} already annotated by {owner} at {rel}:{i + 1}"
    return None


def _owned_addresses(repo_root: Path) -> set[int]:
    path = resolve_repo_path(repo_root, "config/function_ownership.csv")
    if not path.exists():
        return set()
    out: set[int] = set()
    for row in read_pipe_rows(path):
        if (row.get("ownership") or "").strip() != "manual":
            continue
        addr = normalize_hex((row.get("address") or "").strip())
        if addr:
            out.add(int(addr, 16))
    return out


def print_todo(repo_root: Path, cls: str, manifest: dict[str, Any]) -> None:
    """Print the human-judgment TODO list the orchestrator cannot resolve."""
    gen = manifest.get("generated") or {}
    curated = cm.curated_slot_methods(manifest)
    owned = _owned_addresses(repo_root)
    layout = cm.curated_layout(manifest)

    unnamed: list[str] = []
    unported: list[str] = []
    for s in gen.get("slots") or []:
        kind = s.get("kind")
        if kind in ("null", "ilt_thunk"):
            continue
        idx = cm._as_int(s["index"])
        name = s.get("ghidra_name") or ""
        has_curated = idx in curated and curated[idx].get("method")
        if kind in ("new", "override") and not has_curated and _JUNK_NAME.search(name):
            unnamed.append(f"    slot {s['index']} @ {s.get('target')}: name it (Ghidra: {unqualified(name) or '?'})")
        target = normalize_hex(str(s.get("target") or ""))
        if kind in ("new", "override", "scalar_dtor") and target and int(target, 16) not in owned:
            unported.append(f"    slot {s['index']} @ {s.get('target')}: body not owned (port + // FUNCTION marker)")

    base = gen.get("base") or ""
    ancestry = gen.get("ancestry") or []
    base_uncertain = bool(base) and (len(ancestry) < 2 or not any(s.get("kind") == "inherited" for s in gen.get("slots") or []))

    print(f"\n=== recover-class TODO: {cls} ===")
    print(f"  base: {base or '<root>'}  (ancestry: {' -> '.join(str(a) for a in ancestry) or '?'})")
    if base_uncertain:
        print("  !! base edge LOW-CONFIDENCE: no inherited slots resolved against the base "
              "vtable — confirm the base from ctor/dtor sequencing + Mac evidence.")
    if not layout.get("status"):
        print("  !! no curated.layout.status — set recovered/in_progress once the layout is modeled.")
    print(f"  unnamed slots ({len(unnamed)}):")
    for line in unnamed[:60]:
        print(line)
    print(f"  unported bodies ({len(unported)}):")
    for line in unported[:60]:
        print(line)
    if not unnamed and not unported and not base_uncertain:
        print("  (nothing outstanding — slots named + owned, base edge resolved)")


# --------------------------------------------------------------------------- #
# New-class scaffolding (header + cpp from the manifest)
# --------------------------------------------------------------------------- #


def scaffold_new_class(repo_root: Path, cls: str, manifest: dict[str, Any], write: bool) -> int:
    from tools.workflow import class_codegen as bc

    gen = manifest.get("generated") or {}
    base = gen.get("base") or "TObject"
    vtable_addr = gen.get("vtable_addr") or "0x00000000"
    ancestry = [str(a) for a in (gen.get("ancestry") or [cls, base])]
    rtti = {"immediate_base": base, "ancestry": ancestry, "root": gen.get("root") or "TObject"}
    scaffold_issues = source_base_scaffold_issues(cls, manifest)
    vtable_collision = existing_vtable_annotation(repo_root, cls, vtable_addr)
    if vtable_collision:
        scaffold_issues.append(vtable_collision)

    slots = classified_from_manifest(manifest, repo_root)
    owned = [s for s in slots if s.kind in ("override", "new", "scalar_dtor")]
    header_text = bc.render_header(cls, base, vtable_addr, slots, rtti=rtti)
    header_text = header_text.rstrip("\n") + "\n\n" + render_generated_block(manifest) + "\n"
    cpp_text = bc.render_cpp(cls, slots)

    hpath = header_path(repo_root, cls)
    cpp_path = resolve_repo_path(repo_root, f"src/game/{cls}.cpp")
    sym_plan = bc.plan_symbols(resolve_repo_path(repo_root, "config/symbols.csv"), owned, cls)
    own_plan = bc.plan_ownership(
        resolve_repo_path(repo_root, "config/function_ownership.csv"), owned, f"src/game/{cls}.cpp"
    )

    if not write:
        print(f"gen-class {cls}: NEW class (no header). Dry-run preview:\n")
        print(f"=== {hpath} ===\n{header_text}")
        print(f"=== {cpp_path} ===\n{cpp_text}")
        print(
            f"\n+ {len(sym_plan.new_rows)} symbols.csv rows, "
            f"~ {len(sym_plan.updated_rows)} symbols.csv updates, "
            f"+ {len(own_plan.new_rows)} ownership rows."
        )
        for issue in scaffold_issues:
            print(f"!! scaffold issue: {issue}")
        for collision in own_plan.collisions:
            print(f"!! ownership collision: {collision}")
        print("Pass --write to scaffold.")
        return 0

    if scaffold_issues:
        print(f"gen-class {cls}: refusing to scaffold because the manifest is not a safe new class:")
        for issue in scaffold_issues:
            print(f"  {issue}")
        print("Fix the manifest/class identity before writing the new class.")
        return 1

    if own_plan.collisions:
        print(f"gen-class {cls}: refusing to scaffold because slot bodies are already owned:")
        for collision in own_plan.collisions:
            print(f"  {collision}")
        print("Fix the manifest slot classification/curation before writing the new class.")
        return 1

    hpath.write_text(header_text, encoding="utf-8")
    cpp_path.write_text(cpp_text, encoding="utf-8")
    if sym_plan.new_rows or sym_plan.updated_rows:
        sym_plan.path.write_text(sym_plan.merged_text())
    if own_plan.new_rows:
        own_plan.path.write_text(own_plan.merged_text())
    print(f"gen-class {cls}: scaffolded {hpath} + {cpp_path} and merged CSV rows.")
    print(f"Next: just sync-ownership -> regen-stubs -> build -> vtable {cls} -> gates.")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def gen_class(repo_root: Path, cls: str, write: bool, todo: bool = False) -> int:
    mpath = manifest_path(repo_root, cls)
    if not mpath.exists():
        print(f"gen-class: no manifest {mpath}; run `just dump-manifests --only {cls}` first.")
        return 1
    manifest = cm.load_manifest(mpath)

    if todo:
        print_todo(repo_root, cls, manifest)
        return 0

    block = render_generated_block(manifest)
    hpath = header_path(repo_root, cls)
    if not hpath.exists():
        return scaffold_new_class(repo_root, cls, manifest, write)

    text = hpath.read_text(encoding="utf-8")
    new_text, changed = upsert_block(text, cls, block)
    if not changed:
        print(f"gen-class {cls}: generated block already up to date (no-op).")
        return 0
    if not write:
        print(f"gen-class {cls}: block out of date (pass --write to refresh).")
        print("\n--- new generated block ---")
        print(block)
        return 0
    hpath.write_text(new_text, encoding="utf-8")
    print(f"gen-class {cls}: refreshed generated block in {hpath}.")
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Idempotent manifest-driven class generator.")
    p.add_argument("cls", help="Class name (must have config/classes/<Class>.yml).")
    p.add_argument("--write", action="store_true", help="Apply changes (default: dry-run preview).")
    p.add_argument("--todo", action="store_true", help="Print the human-judgment TODO list and exit.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    return gen_class(repo_root_from_file(__file__), args.cls, args.write, todo=args.todo)


if __name__ == "__main__":
    raise SystemExit(main())
