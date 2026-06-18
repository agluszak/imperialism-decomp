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
  * **New class** (no header yet): emit the full ``bootstrap_class`` skeleton
    (header + ``// FUNCTION:`` stubs) *and* the marked block.

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
from pathlib import Path
from typing import Any

from tools.common import class_manifest as cm
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.workflow.bootstrap_class import unqualified

BLOCK_BEGIN = "// === BEGIN GENERATED ({cls}) — refreshed by `just gen-class {cls}`; do not hand-edit ==="
BLOCK_END = "// === END GENERATED ({cls}) ==="


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
# CLI
# --------------------------------------------------------------------------- #


def gen_class(repo_root: Path, cls: str, write: bool) -> int:
    mpath = manifest_path(repo_root, cls)
    if not mpath.exists():
        print(f"gen-class: no manifest {mpath}; run `just dump-manifests --only {cls}` first.")
        return 1
    manifest = cm.load_manifest(mpath)
    block = render_generated_block(manifest)

    hpath = header_path(repo_root, cls)
    if not hpath.exists():
        print(f"gen-class: header {hpath} does not exist yet (new-class flow not wired here);")
        print("           use `just bootstrap-class` to scaffold a brand-new header, then re-run.")
        print("\n--- would insert generated block ---")
        print(block)
        return 1

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
    return p.parse_args()


def main() -> int:
    args = parse_args()
    return gen_class(repo_root_from_file(__file__), args.cls, args.write)


if __name__ == "__main__":
    raise SystemExit(main())
