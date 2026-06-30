#!/usr/bin/env python3
"""Classify `just vtable` failures and apply deterministic repair helpers.

Dry-run is the default. `--write` only runs existing safe repair paths:

* manifest-driven slot claims via marker-only stubs;
* scalar-deleting-destructor spelling canonicalization;
* unreferenced ILT thunk pruning.

Structural vtable-size problems and referenced ILT thunks are reported for manual
follow-up; they are not edited here. Body promotion is intentionally opt-in because
`just vtable` work should pair slots before porting logic.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from tools.common import class_manifest as cm
from tools.common.pipe_csv import normalize_hex, read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.workflow.class_codegen import (
    ClassifiedSlot,
    drop_externally_declared_declarations,
    plan_ownership,
    plan_symbols,
)
from tools.workflow.gen_class import (
    _definition_head_key,
    _find_block_end,
    _has_immediate_marker_before,
    _is_trivial_unmarked_stub,
    _slot_definition_head,
    classified_from_manifest,
    header_path,
    manifest_path,
    render_generated_block,
    render_generated_decls,
    scalar_dtor_block,
    upsert_block,
    upsert_decls_block,
)


VTABLE_HEADER_RE = re.compile(
    r"^(?P<class>[A-Za-z_][A-Za-z0-9_]*)::`vftable' : "
    r"orig (?P<orig>0x[0-9a-fA-F]+), recomp (?P<recomp>0x[0-9a-fA-F]+)"
)
LARGER_RE = re.compile(
    r"Recomp vtable is larger than orig vtable for "
    r"(?P<class>[A-Za-z_][A-Za-z0-9_]*)::`vftable'"
)
SLOT_RE = re.compile(r"^vtable(?P<byte>0x[0-9a-fA-F]+)")
MINUS_RE = re.compile(
    r": -\((?P<orig>0x[0-9a-fA-F]+) / "
    r"(?P<recomp>no recomp|0x[0-9a-fA-F]+)\)\s+:\s+(?P<name>.*)$"
)
PLUS_RE = re.compile(
    r": \+\((?P<orig>no orig|0x[0-9a-fA-F]+) / "
    r"(?P<recomp>0x[0-9a-fA-F]+)\)\s+:\s+(?P<name>.*)$"
)
ADDR_MARKER_RE = re.compile(
    r"^[ \t]*//\s*(?:"
    r"(?:FUNCTION|STUB)\s*:\s*IMPERIALISM\s+"
    r"|SYNTHETIC:\s*IMPERIALISM\s+"
    r"|GHIDRA_FUNCTION\s+IMPERIALISM\s+"
    r")(?:0x)?([0-9a-fA-F]+)\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class VtableFinding:
    class_name: str
    slot_byte: int | None
    side: str
    orig: str
    recomp: str
    name: str

    @property
    def slot_index(self) -> int | None:
        if self.slot_byte is None:
            return None
        return self.slot_byte // 4


@dataclass
class VtableReport:
    classes: list[str] = field(default_factory=list)
    findings: list[VtableFinding] = field(default_factory=list)
    oversized: set[str] = field(default_factory=set)
    found_count: int | None = None
    not_matching_count: int | None = None


@dataclass(frozen=True)
class FixPlan:
    class_name: str
    kind: str
    safe: bool
    summary: str
    command: str | None = None
    addresses: tuple[str, ...] = ()


def parse_vtable_output(text: str) -> VtableReport:
    report = VtableReport()
    current: str | None = None
    slot_byte: int | None = None

    for line in text.splitlines():
        if m := LARGER_RE.search(line):
            report.oversized.add(m.group("class"))
            continue
        if m := VTABLE_HEADER_RE.match(line):
            current = m.group("class")
            report.classes.append(current)
            slot_byte = None
            continue
        if m := SLOT_RE.match(line):
            slot_byte = int(m.group("byte"), 16)
        if current is None:
            if line.startswith("Vtables found:"):
                report.found_count = int(line.split(":", 1)[1].strip().rstrip("."))
            elif line.startswith("Vtables not matching:"):
                report.not_matching_count = int(line.split(":", 1)[1].strip().rstrip("."))
            continue
        if m := MINUS_RE.search(line):
            report.findings.append(
                VtableFinding(
                    current,
                    slot_byte,
                    "orig",
                    m.group("orig"),
                    m.group("recomp"),
                    m.group("name").strip(),
                )
            )
        elif m := PLUS_RE.search(line):
            report.findings.append(
                VtableFinding(
                    current,
                    slot_byte,
                    "recomp",
                    m.group("orig"),
                    m.group("recomp"),
                    m.group("name").strip(),
                )
            )
        if line.startswith("Vtables found:"):
            report.found_count = int(line.split(":", 1)[1].strip().rstrip("."))
        elif line.startswith("Vtables not matching:"):
            report.not_matching_count = int(line.split(":", 1)[1].strip().rstrip("."))
    return report


_GEN_BLOCK_RE = re.compile(
    r"// === BEGIN GENERATED(?: DECLS)? \([^)]*\) .*?// === END GENERATED(?: DECLS)? \([^)]*\) ===",
    re.DOTALL,
)


def _drop_externally_declared(decls: str, header_text: str, cls: str) -> str:
    return drop_externally_declared_declarations(decls, header_text, cls)

def _ancestry_depth(repo_root: Path, cls: str) -> int:
    """Length of the class's ``generated.ancestry`` chain (class..root..CObject).

    A base always has a strictly shorter ancestry than any class derived from it, so
    sorting the work list by this depth ascending is a valid topological order: every
    ancestor is processed before its descendants. Classes without a manifest sort last
    (depth ``inf``) so the foundation/known classes lead. See the plan's cascade lever:
    fixing a base first lets `base_owned`/oversized mismatches resolve family-wide.
    """
    path = manifest_path(repo_root, cls)
    if not path.exists():
        return 1_000_000
    try:
        manifest = cm.load_manifest(path)
    except Exception as exc:
        print(f"Warning: failed loading manifest for {cls}: {exc}", file=sys.stderr)
        return 1_000_000
    ancestry = (manifest.get("generated") or {}).get("ancestry") or []
    return len(ancestry) or 1_000_000


def order_classes_bases_first(repo_root: Path, classes: list[str]) -> list[str]:
    """Stable sort of ``classes`` so ancestors precede descendants (bases first)."""
    return sorted(classes, key=lambda c: (_ancestry_depth(repo_root, c), c))


def run_vtable(repo_root: Path, class_filter: str | None) -> str:
    cmd = ["just", "vtable"]
    if class_filter:
        cmd.append(class_filter)
    cmd.append("-n")
    proc = subprocess.run(cmd, cwd=repo_root, text=True, capture_output=True, check=False)
    return proc.stdout + proc.stderr


def _manual_owners(repo_root: Path) -> dict[str, str]:
    path = resolve_repo_path(repo_root, "config/function_ownership.csv")
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for row in read_pipe_rows(path):
        if (row.get("ownership") or "").strip() != "manual":
            continue
        addr = normalize_hex((row.get("address") or "").strip())
        if addr:
            out[addr] = (row.get("target_cpp") or "").strip()
    return out


def _manifest_owned_slots(repo_root: Path, cls: str) -> tuple[list[ClassifiedSlot], list[str]]:
    path = manifest_path(repo_root, cls)
    if not path.exists():
        return [], []
    target_cpp = f"src/game/{cls}.cpp"
    owners = _manual_owners(repo_root)
    slots = [
        s
        for s in classified_from_manifest(cm.load_manifest(path), repo_root)
        if s.kind in ("override", "new", "scalar_dtor") and s.target_addr
    ]
    collisions = []
    owned = []
    for slot in slots:
        addr = normalize_hex(slot.target_addr)
        owner = owners.get(addr)
        if owner and owner != target_cpp:
            collisions.append(f"0x{int(addr, 16):08x} already owned by {owner}")
            continue
        owned.append(slot)
    return owned, collisions


def _claimable_manifest_slots(repo_root: Path, cls: str) -> tuple[tuple[str, ...], list[str]]:
    slots, collisions = _manifest_owned_slots(repo_root, cls)
    addresses = tuple(f"0x{int(s.target_addr, 16):08x}" for s in slots)
    return addresses, collisions


def _manifest_slot_kinds(repo_root: Path, cls: str) -> dict[int, tuple[str, str | None]]:
    path = manifest_path(repo_root, cls)
    if not path.exists():
        return {}
    manifest = cm.load_manifest(path)
    base = str((manifest.get("generated") or {}).get("base") or "")
    slots = {}
    for slot in (manifest.get("generated") or {}).get("slots") or []:
        slots[cm._as_int(slot.get("byte") or 0) // 4] = (str(slot.get("kind") or ""), base)
    return slots


def _is_ilt_addr(addr: str) -> bool:
    try:
        value = int(addr, 16)
    except ValueError:
        return False
    return 0x00401000 <= value <= 0x00409FFF


def _slot_addr(slot: ClassifiedSlot) -> int:
    return int(normalize_hex(slot.target_addr), 16)


def _stub_block(cls: str, slot: ClassifiedSlot) -> str:
    addr = _slot_addr(slot)
    if slot.kind == "scalar_dtor":
        return scalar_dtor_block(cls, addr) + f"{cls}::~{cls}() {{}}\n\n"
    assert slot.sig is not None
    lines = [f"// FUNCTION: IMPERIALISM 0x{addr:08x}", f"{slot.sig.definition_head(cls)} {{"]
    if slot.sig.ret.strip() not in ("void", ""):
        lines.append("  return 0;")
    lines.append("}")
    return "\n".join(lines) + "\n\n"


def _strip_or_mark_unmarked_stubs(
    cpp_text: str, cls: str, slots: list[ClassifiedSlot]
) -> tuple[str, set[int]]:
    heads: dict[str, ClassifiedSlot] = {}
    for slot in slots:
        head = _slot_definition_head(cls, slot)
        if head:
            heads[_definition_head_key(head)] = slot
    if not heads:
        return cpp_text, set()

    def has_marker_before_definition(pos: int) -> bool:
        if _has_immediate_marker_before(cpp_text, pos):
            return True
        prefix = cpp_text[:pos].rstrip()
        for line in reversed(prefix.splitlines()[-4:]):
            stripped = line.strip()
            if ADDR_MARKER_RE.match(stripped):
                return True
            if stripped.startswith("//"):
                continue
            break
        return False

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
        if has_marker_before_definition(match.start()):
            continue
        slot = heads.get(_definition_head_key(match.group("head")))
        if slot is None:
            continue
        end = _find_block_end(cpp_text, match.end() - 1)
        if end is None:
            continue
        remove_end = end
        while remove_end < len(cpp_text) and cpp_text[remove_end] in " \t\r\n":
            remove_end += 1
        block = cpp_text[match.start() : end]
        addr = _slot_addr(slot)
        chunks.append(cpp_text[cursor : match.start()])
        if _is_trivial_unmarked_stub(block):
            cursor = remove_end
            continue
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


def _method_name_from_block(block: str, cls: str) -> str | None:
    if f"{cls}::~{cls}(" in block:
        return f"~{cls}"
    m = re.search(rf"\b{re.escape(cls)}::(~?{re.escape(cls)}|[A-Za-z_]\w*)\s*\(", block)
    return m.group(1) if m else None


def _marked_method_addrs(existing: dict[int, str], cls: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for addr, block in existing.items():
        name = _method_name_from_block(block, cls)
        if name:
            out[name] = addr
    return out


def _update_marker_addr(block: str, addr: int, *, synthetic: bool = False) -> str:
    kind = "SYNTHETIC" if synthetic else "FUNCTION"
    return re.sub(
        r"// (?:FUNCTION|SYNTHETIC): IMPERIALISM 0x[0-9a-fA-F]+",
        f"// {kind}: IMPERIALISM 0x{addr:08x}",
        block,
        count=1,
    )


def _merge_marker_stubs(cpp_text: str, cls: str, slots: list[ClassifiedSlot]) -> tuple[str, list[int]]:
    cpp_text, marked = _strip_or_mark_unmarked_stubs(cpp_text, cls, slots)
    matches = list(ADDR_MARKER_RE.finditer(cpp_text))
    preamble = cpp_text[: matches[0].start()] if matches else cpp_text
    existing: dict[int, str] = {}
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(cpp_text)
        addr = int(match.group(1), 16)
        existing[addr] = cpp_text[start:end].rstrip() + "\n\n"

    def _scalar_dtor_stub(addr: int) -> str:
        # If the class already defines a real `~Class()` (a hand-ported destructor at the
        # `??1` address), MSVC generates the `??_G` scalar deleting destructor from it, so
        # seeding a second `~Class(){}` body is a duplicate definition (C2084). In that
        # case emit the SYNTHETIC marker only (it claims the `??_G` address for pairing).
        real_dtor = any(
            a != addr and f"{cls}::~{cls}(" in blk for a, blk in existing.items()
        )
        if real_dtor:
            return scalar_dtor_block(cls, addr) + "\n"
        return _stub_block(cls, slot)

    has_dtor_body = any(f"{cls}::~{cls}(" in blk for blk in existing.values())
    method_addrs = _marked_method_addrs(existing, cls)
    claimed = sorted(marked)
    for slot in sorted(slots, key=_slot_addr):
        addr = _slot_addr(slot)
        if slot.kind == "scalar_dtor":
            if has_dtor_body:
                if addr not in existing:
                    existing[addr] = scalar_dtor_block(cls, addr) + "\n"
                    claimed.append(addr)
                elif f"{cls}::~{cls}(" not in existing[addr]:
                    existing[addr] = scalar_dtor_block(cls, addr) + "\n"
                    claimed.append(addr)
                continue
        elif slot.sig is not None and (old_addr := method_addrs.get(slot.sig.name)) is not None:
            if old_addr != addr:
                block = existing.pop(old_addr)
                synthetic = block.lstrip().startswith("// SYNTHETIC:")
                existing[addr] = _update_marker_addr(block.rstrip(), addr, synthetic=synthetic) + "\n\n"
                method_addrs[slot.sig.name] = addr
                claimed.append(addr)
            continue
        block = existing.get(addr)
        if block is not None:
            if slot.kind == "scalar_dtor" and f"{cls}::~{cls}(" not in block:
                existing[addr] = (
                    _scalar_dtor_stub(addr) if slot.kind == "scalar_dtor" else _stub_block(cls, slot)
                )
                claimed.append(addr)
            continue
        if slot.sig is not None and slot.sig.name in method_addrs:
            continue
        existing[addr] = _scalar_dtor_stub(addr) if slot.kind == "scalar_dtor" else _stub_block(cls, slot)
        claimed.append(addr)
        if slot.sig is not None:
            method_addrs[slot.sig.name] = addr
        if slot.kind == "scalar_dtor":
            has_dtor_body = True

    body = "".join(existing[a] for a in sorted(existing))
    if preamble and not preamble.endswith("\n"):
        preamble += "\n"
    return preamble.rstrip() + "\n\n" + body.rstrip() + "\n", sorted(set(claimed))


def claim_vtable_slots(repo_root: Path, cls: str, write: bool) -> int:
    path = manifest_path(repo_root, cls)
    if not path.exists():
        print(f"vtable-autofix: no manifest {path}")
        return 1
    manifest = cm.load_manifest(path)
    slots, collisions = _manifest_owned_slots(repo_root, cls)
    # `collisions` are override/new slots whose address is owned by another class's .cpp
    # (shared slot bodies are common). These are NOT claimed here; the header still
    # declares them and `reconcile_unmarked_stubs` emits an unmarked definition so the
    # vtable links. Only a collision on a slot we actually try to claim (own_plan, below)
    # aborts. Report the foreign-owned slots for visibility but proceed.
    if collisions:
        print(f"vtable-autofix {cls}: {len(collisions)} foreign-owned slot(s) left to reconcile:")
        for collision in collisions:
            print(f"  {collision}")

    hpath = header_path(repo_root, cls)
    cpp_path = resolve_repo_path(repo_root, f"src/game/{cls}.cpp")
    if not hpath.exists():
        print(f"vtable-autofix {cls}: missing header {hpath} (skip)")
        return 0

    header_text = hpath.read_text(encoding="utf-8")
    new_header, block_changed = upsert_block(header_text, cls, render_generated_block(manifest))
    decls = render_generated_decls(
        manifest,
        [s for s in classified_from_manifest(manifest, repo_root) if s.kind not in ("null", "ilt_thunk")],
    )
    # Drop generated decl lines for members a hand-curated header already declares
    # outside the generated blocks (e.g. GetRuntimeClass / the dtor on curated classes),
    # otherwise the regenerated block double-declares them (MSVC C2535).
    decls = _drop_externally_declared(decls, header_text, cls)
    new_header, decls_changed = upsert_decls_block(new_header, cls, decls)

    cpp_text = (
        cpp_path.read_text(encoding="utf-8")
        if cpp_path.exists()
        else f'#include "game/{cls}.h"\n'
    )
    new_cpp, claimed = _merge_marker_stubs(cpp_text, cls, slots)
    # The header DECLS now use ancestry-resolved override names; an override slot whose
    # address is owned by another class keeps an *unmarked* stub here, so reconcile those
    # (drop stubs renamed away, emit unmarked stubs for foreign-owned slots) to keep the
    # .cpp definitions in step with the header — otherwise header/cpp names diverge.
    from tools.workflow.gen_class import reconcile_unmarked_stubs

    all_slots = classified_from_manifest(manifest, repo_root)
    owned_addrs = {normalize_hex(s.target_addr) for s in slots}
    foreign_slots = [
        s
        for s in all_slots
        if s.kind in ("override", "new")
        and s.sig is not None
        and normalize_hex(s.target_addr) not in owned_addrs
    ]
    valid_names = {s.sig.name for s in all_slots if s.kind in ("override", "new") and s.sig}
    valid_names.add(f"~{cls}")
    new_cpp = reconcile_unmarked_stubs(new_cpp, cls, foreign_slots, valid_names, all_slots)

    sym_plan = plan_symbols(resolve_repo_path(repo_root, "config/symbols.csv"), slots, cls)
    own_plan = plan_ownership(
        resolve_repo_path(repo_root, "config/function_ownership.csv"),
        slots,
        f"src/game/{cls}.cpp",
    )
    if own_plan.collisions:
        print(f"vtable-autofix {cls}: refusing slot claim due to ownership collisions:")
        for collision in own_plan.collisions:
            print(f"  {collision}")
        return 1

    print(f"vtable-autofix {cls}: claim {len(slots)} slot(s)")
    if claimed:
        print("  marker stubs: " + ", ".join(f"0x{a:08x}" for a in claimed))
    print(f"  header {'changed' if (block_changed or decls_changed) else 'up to date'}")
    print(f"  cpp {'changed' if new_cpp != cpp_text else 'up to date'}")
    if sym_plan.new_rows or sym_plan.updated_rows:
        print(f"  symbols rows: +{len(sym_plan.new_rows)} ~{len(sym_plan.updated_rows)}")
    if own_plan.new_rows:
        print(f"  ownership rows: +{len(own_plan.new_rows)}")

    if not write:
        return 0
    if block_changed or decls_changed:
        hpath.write_text(new_header, encoding="utf-8")
    if new_cpp != cpp_text:
        cpp_path.parent.mkdir(parents=True, exist_ok=True)
        cpp_path.write_text(new_cpp, encoding="utf-8")
    if sym_plan.new_rows or sym_plan.updated_rows:
        sym_plan.path.write_text(sym_plan.merged_text())
    if own_plan.new_rows:
        own_plan.path.write_text(own_plan.merged_text())
    return 0


def _ilt_target_is_claimed(repo_root: Path, ilt_addr: str) -> bool:
    """True when the ILT thunk address is claimed in function_ownership.csv."""
    path = resolve_repo_path(repo_root, "config/function_ownership.csv")
    if not path.exists():
        return False
    needle = normalize_hex(ilt_addr).lower()
    for row in read_pipe_rows(path):
        if normalize_hex(row.get("address", "")).lower() == needle:
            return True
    return False


def plan_for_classes(repo_root: Path, report: VtableReport, classes: list[str]) -> list[FixPlan]:
    plans: list[FixPlan] = []
    seen: set[tuple[str, str, str]] = set()
    findings_by_class: dict[str, list[VtableFinding]] = {
        cls: [f for f in report.findings if f.class_name == cls] for cls in classes
    }

    for cls in classes:
        if (repo_root / "config" / "classes" / f"{cls}.yml").exists():
            claimable, collisions = _claimable_manifest_slots(repo_root, cls)
            if claimable:
                # Foreign-owned (collision) slots are reconciled as unmarked stubs, not
                # claimed, so they no longer block the safe claim of the owned slots.
                summary = f"claim {len(claimable)} manifest-owned vtable slot(s) with marker stubs"
                if collisions:
                    summary += f"; reconcile {len(collisions)} foreign-owned slot(s)"
                plans.append(
                    FixPlan(
                        cls,
                        "slot_promotion",
                        True,
                        summary,
                        f"just vtable-autofix {cls} --write",
                        claimable,
                    )
                )
            elif collisions:
                # No owned slots to claim, but header decls + foreign reconcile still need
                # to run to keep the .cpp in step with resolver-corrected override names.
                plans.append(
                    FixPlan(
                        cls,
                        "slot_promotion",
                        True,
                        f"reconcile {len(collisions)} foreign-owned vtable slot(s)",
                        f"just vtable-autofix {cls} --write",
                    )
                )

        class_findings = findings_by_class.get(cls, [])
        if any(
            "scalar_deleting_destructor" in f.name or "AndMaybeFree" in f.name
            for f in class_findings
        ):
            key = (cls, "scalar_dtor", "")
            if key not in seen:
                plans.append(
                    FixPlan(
                        cls,
                        "scalar_dtor",
                        True,
                        "canonicalize scalar deleting destructor names/comments",
                        "just correct-scalar-dtors",
                    )
                )
                seen.add(key)

        ilt = [
            f
            for f in class_findings
            if f.side == "orig" and f.orig.startswith("0x") and _is_ilt_addr(f.orig)
        ]
        if ilt:
            referenced = [f for f in ilt if _ilt_target_is_claimed(repo_root, f.orig)]
            unreferenced = [f for f in ilt if f not in referenced]
            if referenced:
                addrs = ", ".join(f"0x{f.orig}" for f in referenced[:6])
                plans.append(
                    FixPlan(
                        cls,
                        "ilt_thunk_referenced",
                        False,
                        f"referenced ILT slot(s) need callsite repoint + symbols row drop ({addrs})",
                        "just repair-thunk-migration <addr>",
                        tuple(f.orig for f in referenced),
                    )
                )
            if unreferenced:
                plans.append(
                    FixPlan(
                        cls,
                        "ilt_thunk",
                        True,
                        f"prune unreferenced ILT thunk rows ({len(unreferenced)} slot(s))",
                        "just prune-ilt-thunks",
                        tuple(f.orig for f in unreferenced),
                    )
                )

        slot_kinds = _manifest_slot_kinds(repo_root, cls)
        inherited = []
        for f in class_findings:
            if f.slot_index is None:
                continue
            kind_base = slot_kinds.get(f.slot_index)
            if kind_base and kind_base[0] == "inherited" and kind_base[1]:
                inherited.append((f.slot_index, kind_base[1]))
        if inherited:
            slots = ", ".join(f"0x{idx:x}->{base}" for idx, base in sorted(set(inherited))[:6])
            plans.append(
                FixPlan(
                    cls,
                    "base_owned",
                    False,
                    f"mismatch is inherited; fix nearest owning base first ({slots})",
                )
            )

        if cls in report.oversized:
            plans.append(
                FixPlan(
                    cls,
                    "oversized_vtable",
                    False,
                    "recompiled vtable is larger than original; inspect declaration/order/base model",
                )
            )
    return plans


def _run_just(repo_root: Path, *args: str) -> int:
    print("$ just " + " ".join(args))
    return subprocess.run(["just", *args], cwd=repo_root, check=False).returncode


def apply_plans(repo_root: Path, plans: list[FixPlan], verify: bool, promote_bodies: bool) -> int:
    rc = 0
    # Preserve the (topological) order in which plans were produced — a base must be
    # regenerated before its descendants so each descendant header regenerates against
    # the corrected base. dict.fromkeys keeps first-seen order while de-duplicating.
    slot_classes = list(
        dict.fromkeys(p.class_name for p in plans if p.kind == "slot_promotion" and p.safe)
    )
    if any(p.kind == "scalar_dtor" and p.safe for p in plans):
        rc = rc or _run_just(repo_root, "correct-scalar-dtors")
    if any(p.kind == "ilt_thunk" and p.safe for p in plans):
        rc = rc or _run_just(repo_root, "prune-ilt-thunks")
    for cls in slot_classes:
        if promote_bodies:
            rc = rc or _run_just(repo_root, "gen-class", cls, "--write")
        else:
            rc = rc or claim_vtable_slots(repo_root, cls, write=True)
    if rc != 0 or not verify:
        return rc
    for target in ("sync-ownership", "regen-stubs", "build", "detect"):
        rc = rc or _run_just(repo_root, target)
        if rc:
            return rc
    for cls in slot_classes:
        rc = rc or _run_just(repo_root, "vtable", cls)
        if rc:
            return rc
    return rc or _run_just(repo_root, "gates")


def print_plans(report: VtableReport, plans: list[FixPlan], write: bool) -> None:
    if report.found_count is not None and report.not_matching_count is not None:
        print(
            f"vtable-autofix: vtables found {report.found_count}, "
            f"not matching {report.not_matching_count}"
        )
    if not plans:
        print("vtable-autofix: no actionable findings.")
        return
    for plan in plans:
        state = "safe" if plan.safe else "manual"
        print(f"{plan.class_name}: [{state}] {plan.kind}: {plan.summary}")
        if plan.addresses:
            print("  addresses: " + ", ".join(plan.addresses[:12]))
        if plan.command:
            prefix = "  run:" if write else "  would run:"
            print(f"{prefix} {plan.command}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("class_filter", nargs="?", help="Class/filter to pass to `just vtable`.")
    parser.add_argument("--all", action="store_true", help="Analyze all classes from vtable output.")
    parser.add_argument("--write", action="store_true", help="Apply safe fixes.")
    parser.add_argument(
        "--promote-bodies",
        action="store_true",
        help="Opt into gen-class body promotion for manifest slots. Default is marker-only.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="After --write, run sync/build/detect/vtable/gates.",
    )
    parser.add_argument("--limit", type=int, default=0, help="Analyze at most N classes.")
    parser.add_argument(
        "--ordered",
        action="store_true",
        help="Process classes bases-first (by manifest ancestry depth) so base fixes "
        "cascade to descendants. Implied by --all.",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=0,
        help="When --write is set, repeat autofix → sync-ownership → regen-stubs → build "
        "and stop when the aggregate not-matching vtable count stabilizes or rounds "
        "are exhausted. 0 disables the loop (single pass). Implies --all when no "
        "class filter is given.",
    )
    parser.add_argument("--vtable-log", type=Path, help="Use an existing `just vtable -n` log.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.class_filter and not args.all and not args.vtable_log and not args.max_rounds:
        raise SystemExit("pass a class filter, --all, --max-rounds, or --vtable-log")

    repo_root = repo_root_from_file(__file__)
    if args.max_rounds and not args.write:
        raise SystemExit("--max-rounds requires --write")
    if args.max_rounds:
        args.all = True
        args.ordered = True

    max_rounds = args.max_rounds if args.max_rounds else 1
    prev_not_matching: int | None = None
    rc = 0

    for round_idx in range(1, max_rounds + 1):
        if args.max_rounds:
            print(f"vtable-autofix: round {round_idx}/{max_rounds}")

        output = (
            args.vtable_log.read_text(encoding="utf-8", errors="ignore")
            if args.vtable_log and round_idx == 1
            else run_vtable(repo_root, None if args.all or args.max_rounds else args.class_filter)
        )
        report = parse_vtable_output(output)
        classes = report.classes
        if args.class_filter and args.class_filter not in classes:
            classes = [c for c in classes if args.class_filter.lower() in c.lower()]
        if args.ordered or args.all or args.max_rounds:
            classes = order_classes_bases_first(repo_root, classes)
        if args.limit:
            classes = classes[: args.limit]
        plans = plan_for_classes(repo_root, report, classes)
        print_plans(report, plans, args.write)

        if report.not_matching_count is not None and args.max_rounds:
            delta = (
                ""
                if prev_not_matching is None
                else f" (delta {report.not_matching_count - prev_not_matching:+d})"
            )
            print(
                f"vtable-autofix: not matching {report.not_matching_count}{delta}"
            )
            if (
                prev_not_matching is not None
                and report.not_matching_count == prev_not_matching
            ):
                print("vtable-autofix: count stable; stopping early")
                break
            prev_not_matching = report.not_matching_count

        if not args.write:
            return 0

        rc = apply_plans(
            repo_root,
            plans,
            verify=args.verify or bool(args.max_rounds),
            promote_bodies=args.promote_bodies,
        )
        if args.max_rounds:
            for target in ("sync-ownership", "regen-stubs", "build"):
                rc = rc or _run_just(repo_root, target)
                if rc:
                    return rc
        elif rc != 0:
            return rc

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
