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
from tools.common.thunk_names import ThunkResolver, load_thunk_map
from tools.workflow.shape_body import shape_body
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
_IDENT_RE = re.compile(r"^[A-Za-z_~][A-Za-z0-9_]*$")
# Provisional Ghidra names shaped like banned construction bridges (the
# construction-antipattern gate's `bridge_name` rule). A shape-only stub is not a real
# bridge, so neutralize the name rather than asserting one.
_BRIDGE_NAME_RE = re.compile(r"Construct\w*AtThis|VCall_\w*Runtime|\w*AndMaybeFree")


def safe_method_name(name: str | None, idx: int) -> str:
    """A valid, non-bridge-shaped C++ method identifier for a slot, or a deterministic
    ``VTableSlotNN``.

    Provisional Ghidra names can contain backticks/apostrophes/spaces (e.g.
    ``'scalar_deleting_destructor'``) that are not valid identifiers, or look like a
    banned construction bridge (``DestructXAndMaybeFree``). Falling back to a name keyed
    only on the slot index keeps it stable across the hierarchy, so an override and the
    parent virtual it overrides still resolve to the same name.
    """
    n = unqualified(name) if name else ""
    if not n or not _IDENT_RE.match(n) or _BRIDGE_NAME_RE.search(n):
        return f"VTableSlot{idx:02X}"
    return n
_CLASS_DECL = re.compile(r"\b(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\b")

BLOCK_BEGIN = "// === BEGIN GENERATED ({cls}) — refreshed by `just gen-class {cls}`; do not hand-edit ==="
BLOCK_END = "// === END GENERATED ({cls}) ==="

DECLS_BEGIN = "// === BEGIN GENERATED DECLS ({cls}) — refreshed by recover-class; do not hand-edit ==="
DECLS_END = "// === END GENERATED DECLS ({cls}) ==="


_SYMBOLS_NAME_CACHE: dict[str, dict[str, tuple[str, str]]] = {}


def _symbols_name_map(repo_root: Path) -> dict[str, tuple[str, str]]:
    """``addr(bare hex) -> (name, prototype)`` from config/symbols.csv.

    symbols.csv is the name registry of record: a hand-ported/curated slot (e.g. a
    vtable method renamed to its real name like ``Select``) is recorded here and in the
    .cpp body, while the manifest still carries the stale Ghidra ``ghidra_name``. The
    codegen prefers this name for owned slots so the generated header decl matches the
    .cpp definition + symbols row (avoids unresolved-external link breaks). Cached per
    repo_root because the sweep resolves many classes (and ancestors recursively)."""
    key = str(repo_root)
    cached = _SYMBOLS_NAME_CACHE.get(key)
    if cached is not None:
        return cached
    out: dict[str, tuple[str, str]] = {}
    path = resolve_repo_path(repo_root, "config/symbols.csv")
    if path.exists():
        for row in read_pipe_rows(path):
            addr = normalize_hex((row.get("address") or "").strip())
            name = (row.get("name") or "").strip()
            if addr and name:
                out[addr] = (name, (row.get("prototype") or "").strip())
    _SYMBOLS_NAME_CACHE[key] = out
    return out


_DEFAULTED_DECL_CACHE: dict[str, dict[str, str]] = {}
# A method decl whose parameter list carries default arguments, e.g.
#   bool IsSelected(short value = -1, bool refreshNow = true) override;
_DEFAULTED_DECL_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;{}]*=[^;{}]*)\)\s*(?:const)?\s*(?:override)?\s*;"
)


def _handcurated_defaulted_args(repo_root: Path) -> dict[str, str]:
    """``method name -> args-with-defaults`` scanned from every game header decl that
    carries default arguments. A slot resolved to such a method must reproduce the
    defaults, or hand-ported callers that omit those arguments fail to compile (C2660).
    Cached per repo_root (one scan amortized across the whole sweep)."""
    key = str(repo_root)
    cached = _DEFAULTED_DECL_CACHE.get(key)
    if cached is not None:
        return cached
    out: dict[str, str] = {}
    include_dir = resolve_repo_path(repo_root, "include/game")
    if include_dir.is_dir():
        for hpath in include_dir.glob("*.h"):
            for line in hpath.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if s.startswith("//") or "=" not in s or "(" not in s:
                    continue
                m = _DEFAULTED_DECL_RE.search(s)
                if m and m.group("name") not in out:
                    out[m.group("name")] = m.group("args").strip()
    _DEFAULTED_DECL_CACHE[key] = out
    return out


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
    return safe_method_name(name, idx) if name else "?"


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
    sym_names = _symbols_name_map(repo_root) if repo_root is not None else {}
    out: list[ClassifiedSlot] = []
    for s in (manifest.get("generated") or {}).get("slots") or []:
        idx = cm._as_int(s["index"])
        target = norm_addr(str(s.get("target") or "0x0"))
        kind = s.get("kind") or "new"
        cur = curated.get(idx)
        qualified = (cur or {}).get("method") or s.get("ghidra_name")
        proto = (cur or {}).get("prototype") or s.get("prototype")
        # symbols.csv is the name registry of record: when an owned slot has a real
        # (non-junk) curated name there, it matches the .cpp body + ownership, so prefer
        # it over the manifest's stale Ghidra name. Manifest curated.slots still wins;
        # ancestor-header resolution (overrides only) runs later and can still override.
        if not (cur or {}).get("method") and kind in ("override", "new"):
            sym = sym_names.get(target)
            if sym:
                sym_simple = unqualified(sym[0])
                if (
                    _IDENT_RE.match(sym_simple)
                    and not _JUNK_NAME.search(sym_simple)
                    and not sym[0].endswith("destructor'")
                ):
                    qualified = sym[0]
                    if sym[1]:
                        proto = sym[1]
        preferred = safe_method_name(qualified, idx)
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
        out = _match_ancestor_header_return_types(out, manifest, repo_root)
        out = _apply_defaulted_args(out, repo_root)
    out = _dedupe_method_names(out)
    return out


def _apply_defaulted_args(
    slots: list[ClassifiedSlot], repo_root: Path
) -> list[ClassifiedSlot]:
    """If a slot's resolved method is declared elsewhere with default arguments, adopt
    the defaulted parameter list so hand-ported callers that omit those args compile."""
    defaults = _handcurated_defaulted_args(repo_root)
    if not defaults:
        return slots
    out: list[ClassifiedSlot] = []
    for s in slots:
        if s.kind in ("override", "new") and s.sig is not None and s.sig.name in defaults:
            out.append(replace(s, sig=replace(s.sig, args=defaults[s.sig.name])))
        else:
            out.append(s)
    return out


def _dedupe_method_names(slots: list[ClassifiedSlot]) -> list[ClassifiedSlot]:
    """Disambiguate override/new slots that share a method name.

    Distinct vtable slots often carry the same provisional Ghidra name (shared
    dispatch/no-op bodies), which would emit duplicate member declarations (C2535).
    Suffix every colliding name with its slot index — deterministic, so a parent and
    child that share the collision still resolve to the same overriding name."""
    counts: dict[str, int] = {}
    for s in slots:
        if s.kind in ("override", "new") and s.sig is not None:
            counts[s.sig.name] = counts.get(s.sig.name, 0) + 1
    if not any(c > 1 for c in counts.values()):
        return slots
    out: list[ClassifiedSlot] = []
    for s in slots:
        if s.kind in ("override", "new") and s.sig is not None and counts[s.sig.name] > 1:
            out.append(replace(s, sig=replace(s.sig, name=f"{s.sig.name}_{s.index:02x}")))
        else:
            out.append(s)
    return out


_VIRTUAL_DECL_RE = re.compile(r"\bvirtual\s+(.+?)\s+(~?[A-Za-z_]\w*)\s*\(")

# A hand-curated/generated virtual decl tagged with its vtable slot index, e.g.
#   virtual void NoOpUiLifecycleHook(int arg);   // 0x37 0x48ab70
#   virtual class TView* OwnerPanel() override;  // 0x16 0x48b180
# The `// 0x<idx>` comment is the authoritative slot the base actually emits the
# virtual at — the manifest's `ghidra_name` for the same slot is a stale cross-class
# label (the source `apply_ancestry_slots` corrects from manifests, but those names are
# junk for inherited slots on hand-curated bases). Parsing the header decl recovers the
# real name+signature so a derived `override` matches the base virtual exactly and MSVC
# reuses the slot instead of appending a new one (the oversized-vtable root cause).
_HEADER_SLOT_DECL_RE = re.compile(
    r"^\s*virtual\s+(?P<decl>.+?)\s*;\s*//\s*0x(?P<idx>[0-9a-fA-F]+)\b"
)


def _ancestor_header_slot_decls(
    manifest: dict[str, Any], repo_root: Path
) -> tuple[dict[int, str], dict[int, Signature]]:
    """Per-slot ``(name, signature)`` parsed from ancestor *headers*, nearest wins.

    Walks ``generated.ancestry`` nearest-first; for each ``virtual ...; // 0x<idx>``
    decl records the first ancestor that names the slot. Destructor slots (``~Class``)
    are skipped — they stay the scalar-deleting-dtor path. The recovered name+signature
    take priority over the manifest's stale ``ghidra_name`` so a derived override binds
    to the base virtual at that slot.
    """
    cls = manifest.get("class")
    ancestry = [str(a) for a in (manifest.get("generated") or {}).get("ancestry") or []]
    names: dict[int, str] = {}
    sigs: dict[int, Signature] = {}
    for anc in ancestry[1:]:  # ancestry[0] is the class itself
        if anc == cls:
            continue
        hpath = header_path(repo_root, anc)
        if not hpath.exists():
            continue
        for line in hpath.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = _HEADER_SLOT_DECL_RE.match(line)
            if not m:
                continue
            idx = int(m.group("idx"), 16)
            if idx in names:
                continue
            decl = m.group("decl")
            # Strip the trailing `override` specifier and any leading `class`/`struct`
            # elaborated-type keyword so parse_prototype reads a clean prototype.
            decl = re.sub(r"\boverride\b", "", decl).strip()
            decl = re.sub(r"\b(class|struct)\s+", "", decl)
            if "~" in decl or "(" not in decl:
                continue
            sig = parse_prototype(decl, fallback_name="")
            if not sig.name or sig.name.startswith("~"):
                continue
            names[idx] = sig.name
            sigs[idx] = sig
    return names, sigs


def _ancestor_header_return_types(manifest: dict[str, Any], repo_root: Path) -> dict[str, str]:
    """``method name -> return type`` from the class's ancestor *headers* (nearest
    wins). A hand-curated base may declare a virtual with a corrected return type
    (e.g. ``char``) that differs from the Ghidra prototype (``undefined``); a derived
    override must use the base's type or MSVC rejects it (C2555)."""
    cls = manifest.get("class")
    ancestry = [str(a) for a in (manifest.get("generated") or {}).get("ancestry") or []]
    out: dict[str, str] = {}
    for anc in ancestry[1:]:
        if anc == cls:
            continue
        hpath = header_path(repo_root, anc)
        if not hpath.exists():
            continue
        for line in hpath.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = _VIRTUAL_DECL_RE.search(line)
            if not m:
                continue
            ret, name = m.group(1).strip(), m.group(2)
            if name.startswith("~") or not ret:
                continue
            out.setdefault(name, ret)
    return out


def _match_ancestor_header_return_types(
    slots: list[ClassifiedSlot], manifest: dict[str, Any], repo_root: Path
) -> list[ClassifiedSlot]:
    ret_map = _ancestor_header_return_types(manifest, repo_root)
    if not ret_map:
        return slots
    out: list[ClassifiedSlot] = []
    for s in slots:
        if (
            s.kind in ("override", "new")
            and s.sig is not None
            and s.sig.name in ret_map
            and ret_map[s.sig.name] != s.sig.ret
        ):
            out.append(replace(s, sig=replace(s.sig, ret=ret_map[s.sig.name])))
        else:
            out.append(s)
    return out


def _ancestor_slot_names(
    manifest: dict[str, Any], repo_root: Path
) -> tuple[dict[int, str], dict[int, Signature], set[int]]:
    """Per-slot ``(qualified_name, signature)`` + scalar-dtor indices from ancestors.

    Walks ``generated.ancestry`` nearest-first; for each slot index records the
    first ancestor that supplies a name, and the first that supplies a signature
    (an ``inherited`` ancestor slot carries a name but no signature, so the two can
    come from different ancestors). Also collects the slot indices that any ancestor
    classifies as the scalar deleting destructor, so a derived class's same slot is
    propagated to ``scalar_dtor`` (it is still the dtor, even when the immediate base
    isn't a source root). Recurses through ``classified_from_manifest`` so each
    ancestor is itself resolved against *its* bases.
    """
    cls = manifest.get("class")
    ancestry = [str(a) for a in (manifest.get("generated") or {}).get("ancestry") or []]
    names: dict[int, str] = {}
    sigs: dict[int, Signature] = {}
    scalar_indices: set[int] = set()
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
            if s.kind == "scalar_dtor":
                scalar_indices.add(s.index)
            if s.qualified_name and s.index not in names:
                names[s.index] = s.qualified_name
            if s.sig is not None and s.index not in sigs:
                sigs[s.index] = s.sig
    return names, sigs, scalar_indices


def apply_ancestry_slots(
    slots: list[ClassifiedSlot], manifest: dict[str, Any], repo_root: Path
) -> list[ClassifiedSlot]:
    """Adopt parent slot names/signatures for un-curated inherited/override slots, and
    propagate an ancestor's scalar-deleting-dtor classification onto the same slot."""
    names, sigs, scalar_indices = _ancestor_slot_names(manifest, repo_root)
    # Header-declared slot names override the manifest-derived ones: a hand-curated base
    # spells the real virtual name in its header (`// 0x<idx>` tagged), while the manifest
    # carries a stale cross-class ghidra_name for the same inherited slot. Using the real
    # name lets a derived override bind to the base slot instead of growing the vtable.
    header_names, header_sigs = _ancestor_header_slot_decls(manifest, repo_root)
    names = {**names, **header_names}
    sigs = {**sigs, **header_sigs}
    if not names and not scalar_indices:
        return slots
    local_curated = set(cm.curated_slot_methods(manifest).keys())

    out: list[ClassifiedSlot] = []
    for slot in slots:
        # The scalar-deleting-dtor slot stays the dtor in every descendant, even when
        # the dump labeled it override/new (its target differs from the root's). Render
        # it as `~Class()`, never as a named method (whose name would be the dtor's).
        if (
            slot.index in scalar_indices
            and slot.index not in local_curated
            and slot.kind in ("override", "new", "inherited")
        ):
            out.append(
                replace(slot, kind="scalar_dtor", sig=None, qualified_name=None, dtor_suspect=False)
            )
            continue
        parent_name = names.get(slot.index)
        if (
            slot.index in local_curated
            or slot.kind not in ("override", "inherited")
            or not parent_name
        ):
            out.append(slot)
            continue
        name = safe_method_name(parent_name, slot.index)
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
            nm = safe_method_name(s.qualified_name, s.index) if s.qualified_name else "?"
            lines.append(
                f"  // slot {s.slot_label} {nm} inherited unchanged (0x{s.target_addr})"
            )
        elif s.kind == "null":
            lines.append(f"  // slot {s.slot_label} (null in original table)")
        elif s.kind == "ilt_thunk":
            nm = safe_method_name(s.qualified_name, s.index) if s.qualified_name else "?"
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
            # `new` slots introduce a fresh virtual (no base slot to override); only
            # `override` slots get the `override` specifier (a no-op on MSVC500 via the
            # compat.h `#define override`, but correct for modern verifying compilers).
            lines.append(
                f"  {s.sig.decl(virtual=True, override=s.kind == 'override')}"
                f" // slot 0x{s.index:02x} 0x{s.target_addr}"
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


# --------------------------------------------------------------------------- #
# Slot application: virtual decls + body promotion/shaping (was emit-class-slots)
# --------------------------------------------------------------------------- #


def _owned_cpp_by_addr(repo_root: Path) -> dict[int, str]:
    """``address -> owning .cpp`` for manual-owned functions (ownership CSV)."""
    path = resolve_repo_path(repo_root, "config/function_ownership.csv")
    if not path.exists():
        return {}
    out: dict[int, str] = {}
    for row in read_pipe_rows(path):
        if (row.get("ownership") or "").strip() != "manual":
            continue
        addr = normalize_hex((row.get("address") or "").strip())
        if addr:
            out[int(addr, 16)] = (row.get("target_cpp") or "").strip()
    return out


def _decl_slots(slots: list[ClassifiedSlot]) -> list[ClassifiedSlot]:
    """Slots that need header declarations (exclude null/ilt_thunk only)."""
    return [s for s in slots if s.kind not in ("null", "ilt_thunk")]


def _body_slots(
    slots: list[ClassifiedSlot], owned: dict[int, str], target_cpp_rel: str
) -> list[ClassifiedSlot]:
    """Slots needing a body claim in this class's .cpp (not owned elsewhere)."""
    out: list[ClassifiedSlot] = []
    for s in slots:
        if s.kind not in ("override", "new", "scalar_dtor"):
            continue
        addr = int(s.target_addr or "0", 16)
        existing = owned.get(addr)
        if existing and existing != target_cpp_rel:
            continue
        out.append(s)
    return out


def _is_scaffold_stub(block: str) -> bool:
    """True if a block is a gen-class scaffold stub safe to replace with a real body.

    The new-class scaffold seeds every owned slot with a ``// FUNCTION:`` placeholder
    carrying this marker; we replace those with the shaped autogen body. Any other
    existing block (a human-edited body, a real port) is left untouched.
    """
    return "TODO(manifest): port the body from Ghidra" in block


def _definition_head_key(head: str) -> str:
    """Whitespace-insensitive key for a simple out-of-line method definition head."""
    return re.sub(r"\s+", "", head.strip())


def _slot_definition_head(cls: str, slot: ClassifiedSlot) -> str | None:
    if slot.kind == "scalar_dtor":
        return f"{cls}::~{cls}()"
    if slot.sig is None:
        return None
    return slot.sig.definition_head(cls)


def _find_block_end(text: str, open_brace: int) -> int | None:
    depth = 0
    for i in range(open_brace, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return None


def _is_trivial_unmarked_stub(block: str) -> bool:
    """True for generated shape-only stubs that are safe to replace with a marker.

    These are intentionally narrower than "any empty function": only unmarked
    definitions with an empty body, a zero return, `(void)param` noise, or the
    generator's TODO scaffold comment are considered generated stubs.
    """
    if re.search(r"//\s*(?:FUNCTION|STUB|SYNTHETIC|GHIDRA_FUNCTION)\s+", block):
        return False
    if "TODO(manifest): port the body from Ghidra" in block:
        return True
    body_start = block.find("{")
    body_end = block.rfind("}")
    if body_start == -1 or body_end == -1 or body_end < body_start:
        return False
    body = block[body_start + 1 : body_end].strip()
    body = re.sub(r"//[^\n]*", "", body)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL).strip()
    if not body:
        return True
    statements = [s.strip() for s in body.split(";") if s.strip()]
    if not statements:
        return True
    for stmt in statements:
        if re.fullmatch(r"\(void\)\s*[A-Za-z_][A-Za-z0-9_]*", stmt):
            continue
        if re.fullmatch(r"return\s+(?:0|nullptr|NULL)", stmt):
            continue
        return False
    return True


def _has_immediate_marker_before(text: str, pos: int) -> bool:
    prefix = text[:pos].rstrip()
    if not prefix:
        return False
    previous = prefix.rsplit("\n", 1)[-1]
    return bool(
        re.match(r"\s*//\s*(?:FUNCTION|STUB|SYNTHETIC|GHIDRA_FUNCTION)\s*[: ]", previous)
    )


def _strip_replaceable_unmarked_stubs(
    cpp_text: str,
    cls: str,
    body_slots: list[ClassifiedSlot],
    autogen: dict[int, str],
) -> tuple[str, set[int]]:
    """Prepare unmarked method definitions for promotion.

    `gen-class --no-bodies` emits plain out-of-line methods so MSVC creates a vtable
    without claiming addresses. A later body-promotion pass must replace those
    definitions with marked bodies, not append duplicates. Trivial generated stubs
    are removed so a shaped body can be inserted. Nontrivial matching definitions get
    a marker inserted in place and are otherwise left intact.
    """
    replaceable_heads: dict[str, ClassifiedSlot] = {}
    for slot in body_slots:
        addr = int(slot.target_addr or "0", 16)
        if slot.kind != "scalar_dtor" and addr not in autogen:
            continue
        head = _slot_definition_head(cls, slot)
        if head:
            replaceable_heads[_definition_head_key(head)] = slot
    if not replaceable_heads:
        return cpp_text, set()

    pattern = re.compile(
        rf"^[ \t]*(?P<head>[^\n;{{}}]*\b{re.escape(cls)}::"
        rf"(?:~{re.escape(cls)}|[A-Za-z_][A-Za-z0-9_]*)\s*"
        rf"\([^;{{}}]*\)\s*(?:const)?\s*)\{{",
        re.MULTILINE,
    )
    chunks: list[str] = []
    cursor = 0
    marked: set[int] = set()
    for match in pattern.finditer(cpp_text):
        if _has_immediate_marker_before(cpp_text, match.start()):
            continue
        key = _definition_head_key(match.group("head"))
        slot = replaceable_heads.get(key)
        if slot is None:
            continue
        end = _find_block_end(cpp_text, match.end() - 1)
        if end is None:
            continue
        # Remove following blank lines with the generated block to avoid accumulating
        # whitespace when the promoted marked body is inserted in address order.
        remove_end = end
        while remove_end < len(cpp_text) and cpp_text[remove_end] in " \t\r\n":
            remove_end += 1
        block = cpp_text[match.start() : end]
        addr = int(slot.target_addr or "0", 16)
        if _is_trivial_unmarked_stub(block):
            chunks.append(cpp_text[cursor : match.start()])
            cursor = remove_end
            continue
        chunks.append(cpp_text[cursor : match.start()])
        if slot.kind == "scalar_dtor":
            chunks.append(scalar_dtor_block(cls, addr))
        else:
            chunks.append(f"// FUNCTION: IMPERIALISM 0x{addr:08x}\n")
        chunks.append(block)
        cursor = end
        marked.add(addr)
    if cursor == 0:
        return cpp_text, set()
    chunks.append(cpp_text[cursor:])
    return "".join(chunks), marked


def scalar_dtor_block(cls: str, addr: int) -> str:
    return (
        f"// SYNTHETIC: IMPERIALISM 0x{addr:08x}\n"
        f"// {cls}::`scalar deleting destructor'\n"
    )


# A marked block whose function body is empty or a bare `return 0;` — an autofix/
# shape-only slot claim with no real ported logic. Such a stub may carry a stale method
# name from before the ancestry resolver corrected the slot's override name, so its head
# is safe to re-render from the current signature (the body holds nothing to preserve).
_TRIVIAL_STUB_BODY_RE = re.compile(r"\{\s*(?:return\s+0\s*;\s*)?\}")


def _is_trivial_marked_stub(block: str) -> bool:
    # Exactly one brace-pair holding nothing but an optional `return 0;`, and no
    # human TODO/ported content beyond the marker + definition head.
    bodies = _TRIVIAL_STUB_BODY_RE.findall(block)
    if len(bodies) != 1 or "TODO" in block:
        return False
    # Reject anything with a second statement / real logic inside the braces.
    inner = block[block.index("{") + 1 : block.rindex("}")]
    stripped = re.sub(r"return\s+0\s*;", "", inner).strip()
    return stripped == ""


def _render_stub_block(cls: str, slot: ClassifiedSlot) -> str:
    if slot.kind == "scalar_dtor":
        return scalar_dtor_block(cls, int(slot.target_addr or "0", 16)) + f"{cls}::~{cls}() {{}}\n\n"
    assert slot.sig is not None
    addr = int(slot.target_addr or "0", 16)
    body = " return 0; " if slot.sig.ret.strip() not in ("void", "") else ""
    return (
        f"// FUNCTION: IMPERIALISM 0x{addr:08x}\n"
        f"{slot.sig.definition_head(cls)} {{{body}}}\n\n"
    )


def _stub_head_matches(block: str, cls: str, slot: ClassifiedSlot) -> bool:
    """True if a trivial stub block already declares the slot's current method head."""
    if slot.kind == "scalar_dtor":
        return f"{cls}::~{cls}(" in block
    if slot.sig is None:
        return True
    return f"{cls}::{slot.sig.name}(" in block


def reconcile_unmarked_stubs(
    cpp_text: str, cls: str, foreign_slots: list[ClassifiedSlot], valid_names: set[str]
) -> str:
    """Keep unmarked shape-only stubs in sync with the (resolver-corrected) slot names.

    A foreign-owned override/new slot (its address is claimed by another class's .cpp)
    cannot carry a `// FUNCTION:` marker here, but the class still needs its own
    out-of-line definition so the vtable links. When the ancestry resolver renames such
    a slot to the base-virtual name, the old unmarked stub becomes an orphan whose name
    no longer matches the header decl. This pass (1) drops unmarked trivial stubs of
    ``cls::Name`` whose ``Name`` is no longer a declared method, and (2) emits an
    unmarked stub for every foreign-owned slot missing one. Marked blocks and non-trivial
    human bodies are untouched.
    """
    pattern = re.compile(
        rf"^[ \t]*(?P<head>[^\n;{{}}]*\b{re.escape(cls)}::"
        rf"(?P<name>~?[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{{}}]*\)\s*(?:const)?\s*)\{{",
        re.MULTILINE,
    )
    # Foreign-slot names are re-emitted below with the canonical (resolver-corrected)
    # signature, so any trivial stub carrying one is dropped here even if its name is
    # valid — its signature may be stale (e.g. `VTableSlot73(char)` vs the header's
    # `VTableSlot73()`), which would otherwise mismatch the decl (C2511).
    foreign_names = {s.sig.name for s in foreign_slots if s.sig is not None}
    chunks: list[str] = []
    cursor = 0
    present: set[str] = set()
    for match in pattern.finditer(cpp_text):
        if _has_immediate_marker_before(cpp_text, match.start()):
            continue
        end = _find_block_end(cpp_text, match.end() - 1)
        if end is None:
            continue
        block = cpp_text[match.start() : end]
        name = match.group("name")
        if not _is_trivial_unmarked_stub(block):
            present.add(name)
            continue
        remove_end = end
        while remove_end < len(cpp_text) and cpp_text[remove_end] in " \t\r\n":
            remove_end += 1
        if name in valid_names and name not in foreign_names:
            present.add(name)
            continue
        # Orphaned (renamed away) or stale-signature foreign trivial stub: drop it.
        chunks.append(cpp_text[cursor : match.start()])
        cursor = remove_end
    chunks.append(cpp_text[cursor:])
    out = "".join(chunks)

    missing = [
        s
        for s in foreign_slots
        if s.sig is not None and s.sig.name not in present and s.kind in ("override", "new")
    ]
    if missing:
        blocks: list[str] = []
        for s in sorted(missing, key=lambda x: int(x.target_addr or "0", 16)):
            assert s.sig is not None  # filtered above
            ret_val = " return 0; " if s.sig.ret.strip() not in ("void", "") else ""
            blocks.append(f"{s.sig.definition_head(cls)} {{{ret_val}}}\n\n")
        out = out.rstrip() + "\n\n" + "".join(blocks).rstrip() + "\n"
    return out


def merge_cpp_bodies(
    cpp_text: str,
    cls: str,
    body_slots: list[ClassifiedSlot],
    autogen: dict[int, str],
    resolver: ThunkResolver | None = None,
) -> tuple[str, list[int], list[int]]:
    """Insert/refresh promoted+shaped bodies at ascending address order.

    Returns (text, promoted, missing). Scaffold-stub blocks are replaced with the
    shaped autogen body; human-edited bodies are never clobbered; scalar dtors stay
    SYNTHETIC.
    """
    cpp_text, unmarked_promoted = _strip_replaceable_unmarked_stubs(
        cpp_text, cls, body_slots, autogen
    )
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

    promoted: list[int] = sorted(unmarked_promoted)
    missing: list[int] = []
    for s in sorted(body_slots, key=lambda x: int(x.target_addr or "0", 16)):
        addr = int(s.target_addr or "0", 16)
        is_stub = addr in existing and _is_scaffold_stub(existing[addr])
        # A trivial shape-only stub whose head no longer matches the slot's (resolver-
        # corrected) signature is re-rendered so the .cpp definition tracks the header
        # decl — without this, renaming an override slot to its base-virtual name leaves
        # the .cpp defining the old name (header/cpp divergence → link/override break).
        if (
            addr in existing
            and not is_stub
            and _is_trivial_marked_stub(existing[addr])
            and not _stub_head_matches(existing[addr], cls, s)
        ):
            existing[addr] = _render_stub_block(cls, s)
            promoted.append(addr)
            continue
        if addr in existing and not is_stub:
            continue  # human-owned or already a real body — never clobber
        if s.kind == "scalar_dtor":
            # scalar dtors stay SYNTHETIC (Hard Rule 9); only seed when absent. Normally
            # seed the SYNTHETIC marker *and* an empty `~Class() {}` body so MSVC has a
            # real destructor for the polymorphic vtable. BUT if the class already defines
            # a real `~Class()` (a hand-ported destructor at the `??1` address), seeding a
            # second body is a duplicate definition (C2084): MSVC generates the `??_G`
            # scalar deleting destructor from that real dtor, so the SYNTHETIC slot is
            # marker-only here (it just claims the `??_G` address for reccmp pairing).
            if addr not in existing:
                real_dtor = any(
                    a != addr and f"{cls}::~{cls}(" in blk for a, blk in existing.items()
                )
                existing[addr] = (
                    scalar_dtor_block(cls, addr) + "\n"
                    if real_dtor
                    else _render_stub_block(cls, s)
                )
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


def apply_slots(
    repo_root: Path,
    cls: str,
    manifest: dict[str, Any],
    slots: list[ClassifiedSlot],
    write: bool,
    no_bodies: bool = False,
) -> int:
    """Insert/refresh the GENERATED DECLS block and promote+shape slot bodies.

    Assumes the header already exists (scaffolded or hand-written). Plans and merges
    the symbols + ownership CSV rows for the bodies. Returns a process exit code.

    When ``no_bodies`` is set, the autogen body-shaping step (``merge_cpp_bodies``) is
    skipped: the header DECLS, the symbols/ownership CSV rows, and the compilable
    scaffold stubs already written by ``scaffold_new_class`` are kept, but no raw
    Ghidra decompile is pulled in. This is the shape-only mode used to batch-port a
    class's *vtable* (which still emits + pairs from the stub definitions) while
    deferring the bodies to a later per-class decomp-loop pass.
    """
    from tools.workflow.promote_from_autogen import collect_autogen_blocks
    from tools.workflow import class_codegen as bc

    hpath = header_path(repo_root, cls)
    cpp_path = resolve_repo_path(repo_root, f"src/game/{cls}.cpp")
    target_cpp_rel = f"src/game/{cls}.cpp"

    decl_slots = _decl_slots(slots)
    owned = _owned_cpp_by_addr(repo_root)
    body_slots = _body_slots(slots, owned, target_cpp_rel)

    decls_block = render_generated_decls(manifest, decl_slots)
    header_text = hpath.read_text(encoding="utf-8")
    new_header, header_changed = upsert_decls_block(header_text, cls, decls_block)

    cpp_text = cpp_path.read_text(encoding="utf-8") if cpp_path.exists() else ""
    if no_bodies:
        # Shape-only: leave the scaffold stubs in place; do not read/shape autogen.
        new_cpp, promoted, missing = cpp_text, [], []
    else:
        autogen_dir = resolve_repo_path(repo_root, "src/ghidra_autogen")
        autogen = (
            collect_autogen_blocks(autogen_dir, "IMPERIALISM") if autogen_dir.is_dir() else {}
        )
        resolver = ThunkResolver(
            load_thunk_map(resolve_repo_path(repo_root, "config/thunk_map.csv"))
        )
        new_cpp, promoted, missing = merge_cpp_bodies(
            cpp_text, cls, body_slots, autogen, resolver
        )
        # Keep unmarked stubs for foreign-owned override/new slots in sync with the
        # resolver-corrected names (the header declares them; their addresses are owned
        # by another class's .cpp so they cannot be marked here).
        foreign_slots = [
            s
            for s in slots
            if s.kind in ("override", "new")
            and s not in body_slots
            and s.sig is not None
        ]
        valid_names = {s.sig.name for s in slots if s.kind in ("override", "new") and s.sig}
        valid_names.add(f"~{cls}")
        new_cpp = reconcile_unmarked_stubs(new_cpp, cls, foreign_slots, valid_names)
    cpp_changed = new_cpp != cpp_text

    # Shape-only (no_bodies) never claims ownership/symbols — markers + ownership are
    # part of body porting (deferred), and the slot targets are shared across classes.
    sym_plan = None
    own_plan = None
    if not no_bodies:
        sym_plan = bc.plan_symbols(
            resolve_repo_path(repo_root, "config/symbols.csv"), body_slots, cls
        )
        own_plan = bc.plan_ownership(
            resolve_repo_path(repo_root, "config/function_ownership.csv"),
            [s for s in body_slots if s.kind != "scalar_dtor"],
            target_cpp_rel,
        )

    collisions = own_plan.collisions if own_plan else []
    print(f"gen-class {cls}: slots — decl {len(decl_slots)}, body {len(body_slots)}")
    print(f"  header DECLS {'changed' if header_changed else 'up to date'}")
    print(f"  cpp bodies {'changed' if cpp_changed else 'up to date'}  promoted {len(promoted)}")
    if promoted:
        print("  promoted: " + ", ".join(f"0x{a:08x}" for a in promoted))
    if missing:
        print("  missing autogen (no body to shape): " + ", ".join(f"0x{a:08x}" for a in missing))
    if collisions:
        print("  ownership collisions:")
        for c in collisions:
            print(f"    {c}")

    if not write:
        print("  (dry-run) pass --write to apply slot decls + bodies.")
        return 1 if collisions else 0

    if collisions:
        print("gen-class: refusing --write due to ownership collisions.")
        return 1

    if header_changed:
        hpath.write_text(new_header, encoding="utf-8")
    if cpp_changed:
        cpp_path.parent.mkdir(parents=True, exist_ok=True)
        cpp_path.write_text(new_cpp, encoding="utf-8")
    if sym_plan and (sym_plan.new_rows or sym_plan.updated_rows):
        sym_plan.path.write_text(sym_plan.merged_text())
    if own_plan and own_plan.new_rows:
        own_plan.path.write_text(own_plan.merged_text())
    return 0


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


def scaffold_new_class(
    repo_root: Path, cls: str, manifest: dict[str, Any], write: bool, no_bodies: bool = False
) -> int:
    """Write the structural skeleton (header + GENERATED block + cpp stubs) for a
    brand-new class. Virtual decls + shaped bodies + CSV rows are applied afterward
    by ``apply_slots`` (the single decl/body source). Returns a process exit code;
    1 means "refused / dry-run, do not proceed to apply_slots".

    When ``no_bodies`` is set the cpp is rendered as unmarked shape-only stubs (no
    ``// FUNCTION:``/``// SYNTHETIC:`` markers, no ownership claim).
    """
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

    hpath = header_path(repo_root, cls)
    cpp_path = resolve_repo_path(repo_root, f"src/game/{cls}.cpp")

    # No-clobber: a class implemented inline in an existing .cpp (no header) must
    # never be overwritten by the scaffold.
    if cpp_path.exists():
        scaffold_issues.append(
            f"src/game/{cls}.cpp already exists (class likely implemented inline); "
            "refusing to overwrite"
        )

    slots = classified_from_manifest(manifest, repo_root)
    header_text = bc.render_header(cls, base, vtable_addr, slots, rtti=rtti)
    header_text = header_text.rstrip("\n") + "\n\n" + render_generated_block(manifest) + "\n"
    cpp_text = bc.render_cpp(cls, slots, emit_markers=not no_bodies)

    if not write:
        print(f"gen-class {cls}: NEW class (no header). Dry-run preview:\n")
        print(f"=== {hpath} ===\n{header_text}")
        print(f"=== {cpp_path} ===\n{cpp_text}")
        for issue in scaffold_issues:
            print(f"!! scaffold issue: {issue}")
        print("Pass --write to scaffold (then slot decls + bodies are applied).")
        return 1

    if scaffold_issues:
        print(f"gen-class {cls}: refusing to scaffold because the manifest is not a safe new class:")
        for issue in scaffold_issues:
            print(f"  {issue}")
        print("Fix the manifest/class identity before writing the new class.")
        return 1

    hpath.write_text(header_text, encoding="utf-8")
    cpp_path.write_text(cpp_text, encoding="utf-8")
    print(f"gen-class {cls}: scaffolded {hpath} + {cpp_path}.")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def gen_class(
    repo_root: Path, cls: str, write: bool, todo: bool = False, no_bodies: bool = False
) -> int:
    mpath = manifest_path(repo_root, cls)
    if not mpath.exists():
        print(f"gen-class: no manifest {mpath}; run `just dump-manifests --only {cls}` first.")
        return 1
    manifest = cm.load_manifest(mpath)

    if todo:
        print_todo(repo_root, cls, manifest)
        return 0

    slots = classified_from_manifest(manifest, repo_root)
    block = render_generated_block(manifest)
    hpath = header_path(repo_root, cls)

    # Stage 1: ensure the header structure exists (scaffold new / refresh block).
    if not hpath.exists():
        rc = scaffold_new_class(repo_root, cls, manifest, write, no_bodies=no_bodies)
        if rc != 0:
            return rc  # dry-run preview or refusal — nothing on disk to apply to
    else:
        text = hpath.read_text(encoding="utf-8")
        new_text, changed = upsert_block(text, cls, block)
        if changed:
            if not write:
                print(f"gen-class {cls}: block out of date (pass --write to refresh).")
                print("\n--- new generated block ---")
                print(block)
            else:
                hpath.write_text(new_text, encoding="utf-8")
                print(f"gen-class {cls}: refreshed generated block in {hpath}.")

    # Stage 2: apply virtual decls + promote/shape slot bodies + merge CSV rows.
    return apply_slots(repo_root, cls, manifest, slots, write, no_bodies=no_bodies)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Idempotent manifest-driven class generator.")
    p.add_argument("cls", help="Class name (must have config/classes/<Class>.yml).")
    p.add_argument("--write", action="store_true", help="Apply changes (default: dry-run preview).")
    p.add_argument("--todo", action="store_true", help="Print the human-judgment TODO list and exit.")
    p.add_argument(
        "--no-bodies",
        action="store_true",
        help="Shape-only: emit header/decls + scaffold stubs + CSV rows, but do not "
        "promote/shape autogen function bodies (vtable still emits + pairs).",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    return gen_class(
        repo_root_from_file(__file__),
        args.cls,
        args.write,
        todo=args.todo,
        no_bodies=args.no_bodies,
    )


if __name__ == "__main__":
    raise SystemExit(main())
