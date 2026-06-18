#!/usr/bin/env python3
"""Shared class/vtable code generation primitives for manifest recovery.

This module classifies vtable slots and renders the first-pass C++ scaffold used
by ``tools.workflow.gen_class`` when a manifest describes a class without a
hand-written header yet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from tools.common.pipe_csv import normalize_hex, read_pipe_table

SCALAR_DTOR_MARK = "scalar deleting destructor"

# Ghidra-name fragments that betray a deleting-destructor-shaped slot even when
# the symbol isn't marked `??_G`/`??_E`. These are PROVISIONAL Ghidra names, so we
# only *flag* such slots (never silently reclassify): a real compiler scalar
# deleting destructor must be claimed via `// SYNTHETIC` + a symbols.csv backtick
# name (Hard Rule 9) — never hand-written as a `Destruct*AndMaybeFree` bridge.
_DTOR_NAME_FRAGMENTS = ("andmaybefree", "scalardeletingdestructor", "??_g", "??_e")


def looks_like_deleting_dtor(name: str | None) -> bool:
    """True if a slot's (provisional) name looks like a deleting-destructor bridge.

    Catches the `Destruct<Class>AndMaybeFree` / `??_G` shapes that must become a
    SYNTHETIC scalar-deleting destructor rather than a hand-ported method.
    """
    if not name:
        return False
    low = unqualified(name).lower()
    if any(frag in low for frag in _DTOR_NAME_FRAGMENTS):
        return True
    return low.startswith("destruct") and low.endswith("andmaybefree")


def norm_addr(value: str) -> str:
    """Normalize an address to bare lowercase hex, no 0x prefix, no leading zeros.

    Matches the spelling used in config/symbols.csv (e.g. ``5c2490``) so lookups
    work regardless of whether the input was ``0x005c2490`` or ``5c2490``.
    """
    raw = normalize_hex((value or "").strip())
    if not raw:
        return ""
    try:
        return f"{int(raw, 16):x}"
    except ValueError:
        return raw


# --------------------------------------------------------------------------- #
# Prototype parsing
# --------------------------------------------------------------------------- #


@dataclass
class Signature:
    ret: str
    name: str
    args: str
    const: str  # "" or " const"

    def decl(self, virtual: bool, override: bool) -> str:
        prefix = "virtual " if virtual else ""
        suffix = " override" if override else ""
        return f"{prefix}{self.ret} {self.name}({self.args}){self.const}{suffix};"

    def definition_head(self, class_name: str) -> str:
        return f"{self.ret} {class_name}::{self.name}({self.args}){self.const}"


def parse_prototype(proto: str | None, fallback_name: str) -> Signature:
    """Parse a Ghidra/symbols prototype string into a C++ method Signature.

    Handles forms like ``void __thiscall Foo(int a)``,
    ``CRuntimeClass* __thiscall Bar() const`` and ``undefined Baz()``. Falls back
    to ``void <fallback_name>()`` when the prototype is missing/unparseable.
    """
    proto = (proto or "").strip()
    if "(" not in proto:
        return Signature("void", fallback_name, "", "")

    head, _, rest = proto.partition("(")
    # const lives after the final ')'
    args_part, _, tail = rest.rpartition(")")
    const = " const" if "const" in tail else ""

    args = args_part.strip()
    if args in ("void", ""):
        args = ""

    tokens = head.replace("__thiscall", " ").replace("__cdecl", " ").split()
    if not tokens:
        return Signature("void", fallback_name, args, const)
    name = tokens[-1]
    ret = " ".join(tokens[:-1]).strip() or "void"
    # Defend against backtick names (scalar dtor) leaking in.
    if "`" in name or not re.match(r"^[A-Za-z_~][A-Za-z0-9_]*$", name):
        name = fallback_name
    return Signature(ret, name, args, const)


# --------------------------------------------------------------------------- #
# Slot classification
# --------------------------------------------------------------------------- #


@dataclass
class ClassifiedSlot:
    index: int
    byte_offset: int
    slot_label: str
    target_addr: str  # bare hex, no 0x
    kind: str  # null | inherited | override | new | scalar_dtor | ilt_thunk
    sig: Signature | None
    qualified_name: str | None
    size: int
    prototype: str | None
    decompiled_c: str | None
    base_target: str | None  # bare hex of base's slot target, for inherited comment
    dtor_suspect: bool = False  # name looks like a deleting-destructor bridge (verify SYNTHETIC)


@dataclass
class SymbolRow:
    name: str
    size: str
    type: str
    prototype: str


def index_symbols(symbol_rows: list[dict[str, str]]) -> dict[str, SymbolRow]:
    out: dict[str, SymbolRow] = {}
    for row in symbol_rows:
        addr = norm_addr(row.get("address") or "")
        if addr:
            out[addr] = SymbolRow(
                name=(row.get("name") or "").strip(),
                size=(row.get("size") or "").strip(),
                type=(row.get("type") or "").strip(),
                prototype=(row.get("prototype") or "").strip(),
            )
    return out


def unqualified(name: str) -> str:
    return name.rsplit("::", 1)[-1] if name else name


def classify_slots(
    class_slots: list[dict],
    base_slots: list[dict],
    symbols: dict[str, SymbolRow],
) -> list[ClassifiedSlot]:
    base_targets = {s["index"]: norm_addr(s.get("target_addr", "")) for s in base_slots}
    base_count = len(base_slots)

    out: list[ClassifiedSlot] = []
    for s in class_slots:
        idx = s["index"]
        target = norm_addr(s.get("target_addr", ""))
        sym = symbols.get(target)
        qualified = sym.name if sym else (s.get("ghidra_name") or None)
        proto = sym.prototype if sym else s.get("prototype")
        size = int(s.get("size") or (sym.size if sym and sym.size.isdigit() else 0) or 0)
        base_target = base_targets.get(idx)

        is_scalar = bool(qualified and SCALAR_DTOR_MARK in qualified)

        if s.get("is_null"):
            kind = "null"
        elif s.get("is_thunk"):
            # An ILT/linker jmp stub that resolution could not escape. reccmp
            # auto-resolves these; owning one would break pairing, so never emit
            # a body/marker/CSV row for it.
            kind = "ilt_thunk"
        elif is_scalar:
            kind = "scalar_dtor"
        elif base_target and target == base_target:
            kind = "inherited"
        elif idx < base_count:
            kind = "override"
        else:
            kind = "new"

        fallback = unqualified(qualified) if qualified else f"VTableSlot{idx:02X}"
        sig = parse_prototype(proto, fallback) if kind in ("override", "new") else None

        # Flag (don't reclassify) deleting-destructor-shaped slots that weren't
        # already marked scalar in symbols.csv, so the porter claims them
        # SYNTHETIC instead of hand-writing a banned bridge (Hard Rule 9).
        dtor_suspect = kind in ("override", "new") and looks_like_deleting_dtor(qualified)

        out.append(
            ClassifiedSlot(
                index=idx,
                byte_offset=s["byte_offset"],
                slot_label=s.get("slot_label", f"0x{s['byte_offset']:02x}"),
                target_addr=target,
                kind=kind,
                sig=sig,
                qualified_name=qualified,
                size=size,
                prototype=proto,
                decompiled_c=s.get("decompiled_c"),
                base_target=base_target,
                dtor_suspect=dtor_suspect,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Code generation
# --------------------------------------------------------------------------- #


def render_header(
    class_name: str,
    base_name: str,
    vtable_addr: str,
    slots: list[ClassifiedSlot],
    rtti: dict | None = None,
) -> str:
    rtti = rtti or {}
    base_header = f'#include "game/{base_name}.h"'
    if rtti.get("immediate_base"):
        # Inheritance recovered from the MFC CRuntimeClass chain — cite it.
        edge_comment = (
            f"// TODO(manifest): describe {class_name} and its role. Base edge "
            f"({base_name}) recovered from RTTI CRuntimeClass chain: "
            f"{' -> '.join(rtti.get('ancestry', [class_name, base_name]))}."
        )
    else:
        edge_comment = (
            f"// TODO(manifest): describe {class_name} and its role; confirm the base"
            f" edge ({base_name}) from ctor/dtor sequencing + vtable layout evidence."
        )
    lines = [
        "#pragma once",
        "",
        base_header,
        "",
        edge_comment,
        f"// VTABLE: IMPERIALISM {vtable_addr}",
        f"class {class_name} : public {base_name} {{",
        "public:",
    ]

    new_virtuals = [s for s in slots if s.kind == "new"]

    lines.append(f"  // --- {base_name} overrides ---")
    for s in slots:
        if s.kind == "inherited":
            nm = unqualified(s.qualified_name) if s.qualified_name else "?"
            lines.append(
                f"  // slot {s.slot_label} {nm} inherited from {base_name} unchanged (0x{s.target_addr})"
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
            lines.append(f"  ~{class_name}() override; // slot {s.slot_label} (scalar deleting destructor)")
        elif s.kind == "override":
            assert s.sig is not None
            lines.append(f"  {s.sig.decl(virtual=False, override=True)} // slot {s.slot_label}")

    if new_virtuals:
        lines.append("")
        lines.append(f"  // --- {class_name} virtual functions ---")
        for s in new_virtuals:
            assert s.sig is not None
            lines.append(f"  {s.sig.decl(virtual=True, override=False)} // slot {s.slot_label}")

    lines += [
        "",
        "  // TODO(manifest): add data members from the object slice"
        " (`just slice-discovery " + class_name + " 0xCTOR`).",
        "",
        f"  {class_name}();",
        "};",
        "",
    ]
    return "\n".join(lines)


def _body_seed(s: ClassifiedSlot) -> list[str]:
    out: list[str] = []
    if s.dtor_suspect:
        out.append("  // WARNING(manifest): this slot's name looks like a deleting-destructor")
        out.append("  // bridge. If it is the compiler scalar-deleting destructor (??_G/??_E),")
        out.append("  // do NOT hand-write this body: delete it and claim the address with a")
        out.append("  // standalone `// SYNTHETIC:` block + a symbols.csv backtick name (Hard")
        out.append("  // Rule 9). Only keep a real method here if it is a genuine virtual.")
    if s.decompiled_c:
        out.append("  // TODO(manifest): port/clean the Ghidra decompile below, then")
        out.append("  // run the decomp loop (compare/vtable) before committing.")
        out.append("  /* --- Ghidra decompile seed ---")
        for line in s.decompiled_c.rstrip().splitlines():
            out.append("  " + line)
        out.append("  --- end seed --- */")
    else:
        out.append("  // TODO(manifest): port the body from Ghidra, then run the decomp loop.")
    # Keep the scaffold compilable: non-void slots need a placeholder return.
    if s.sig is not None and s.sig.ret.strip() not in ("void", ""):
        out.append("  return 0; // TODO(manifest): real return value")
    return out


def render_cpp(class_name: str, slots: list[ClassifiedSlot]) -> str:
    lines = [
        f'#include "game/{class_name}.h"',
        "",
        f"// RTTI class descriptor placeholder (see GetRuntimeClass).",
        f'extern "C" char g_pClassDesc{class_name} = 0;',
        "",
    ]

    # Owned bodies emitted in ascending address order (decomplint requirement).
    owned = sorted(
        [s for s in slots if s.kind in ("override", "new", "scalar_dtor")],
        key=lambda s: int(s.target_addr or "0", 16),
    )

    for s in owned:
        if s.kind == "scalar_dtor":
            lines.append(f"// SYNTHETIC: IMPERIALISM 0x{s.target_addr}")
            lines.append(f"// {class_name}::`scalar deleting destructor'")
            lines.append("")
            lines.append(
                "// TODO(manifest): emit the real ~" + class_name + "() with its own"
            )
            lines.append(
                "// FUNCTION: IMPERIALISM 0x<dtor-addr> marker (find the destructor body in"
            )
            lines.append("// Ghidra; it is usually adjacent to the scalar deleting destructor).")
            lines.append("")
            continue
        assert s.sig is not None
        lines.append(f"// FUNCTION: IMPERIALISM 0x{s.target_addr}")
        lines.append(f"{s.sig.definition_head(class_name)} {{")
        lines += _body_seed(s)
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CSV merge
# --------------------------------------------------------------------------- #


@dataclass
class CsvPlan:
    path: Path
    fieldnames: list[str]
    rows: list[dict[str, str]]
    new_rows: list[dict[str, str]] = field(default_factory=list)
    collisions: list[str] = field(default_factory=list)

    def render_new(self) -> str:
        return "\n".join("|".join(r.get(f, "") for f in self.fieldnames) for r in self.new_rows)

    def merged_text(self) -> str:
        merged = list(self.rows)
        for nr in self.new_rows:
            key = int(norm_addr(nr["address"]) or "0", 16)
            pos = len(merged)
            for i, existing in enumerate(merged):
                if int(norm_addr(existing.get("address", "")) or "0", 16) > key:
                    pos = i
                    break
            merged.insert(pos, nr)
        header = "|".join(self.fieldnames)
        body = "\n".join("|".join(r.get(f, "") for f in self.fieldnames) for r in merged)
        return header + "\n" + body + "\n"


def plan_symbols(path: Path, owned: list[ClassifiedSlot], class_name: str) -> CsvPlan:
    fieldnames, rows = read_pipe_table(path)
    plan = CsvPlan(path=path, fieldnames=fieldnames, rows=rows)
    existing = {norm_addr(r.get("address", "")) for r in rows}
    for s in owned:
        target_addr = norm_addr(s.target_addr)
        if not target_addr or target_addr in existing:
            continue
        if s.kind == "scalar_dtor":
            name = f"{class_name}::`scalar deleting destructor'"
            proto = "void* __thiscall `scalar deleting destructor'(unsigned int)"
        else:
            assert s.sig is not None
            name = f"{class_name}::{s.sig.name}"
            proto = s.prototype or f"{s.sig.ret} {s.sig.name}({s.sig.args})"
        plan.new_rows.append(
            {
                "address": target_addr,
                "name": name,
                "size": str(s.size or 1),
                "type": "function",
                "prototype": proto,
            }
        )
        existing.add(target_addr)
    return plan


def plan_ownership(path: Path, owned: list[ClassifiedSlot], target_cpp: str) -> CsvPlan:
    fieldnames, rows = read_pipe_table(path)
    plan = CsvPlan(path=path, fieldnames=fieldnames, rows=rows)
    by_addr = {norm_addr(r.get("address", "")): r for r in rows}
    for s in owned:
        target_addr = norm_addr(s.target_addr)
        if not target_addr:
            continue
        existing = by_addr.get(target_addr)
        if existing is not None:
            owner = (existing.get("target_cpp") or "").strip()
            if owner and owner != target_cpp:
                plan.collisions.append(f"0x{target_addr} already owned by {owner}")
            continue
        plan.new_rows.append(
            {
                "address": target_addr,
                "target_cpp": target_cpp,
                "ownership": "manual",
                "note": "marker_sync",
            }
        )
        by_addr[target_addr] = plan.new_rows[-1]
    return plan
