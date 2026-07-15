#!/usr/bin/env python3
"""Shared class/vtable code generation primitives.

This module classifies vtable slots and renders C++ scaffold (declarations,
stub bodies, symbols/ownership rows) shared by ``shape_body`` and
``source_base_slots``.
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
# name (construction Hard Rule 10) — never hand-written as a `Destruct*AndMaybeFree` bridge.
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
        # SYNTHETIC instead of hand-writing a banned bridge (construction Hard Rule 10).
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


# A type token worth forward-declaring: a game class (``T<Upper>``) or a Ghidra
# struct/class spelled ``<Upper><lower>...`` (e.g. ``CityDialogController``). MFC types
# (``CString``, ``CArchive`` — second char upper) and Windows typedefs (``LONG``,
# ``LPRECT`` — all-caps) are excluded; they come from ``game/mfc.h``.
_FWD_TYPE_RE = re.compile(r"^(?:T[A-Z][A-Za-z0-9_]*|[A-Z][a-z][A-Za-z0-9_]*|astruct_\d+)$")
_PRIMITIVE_TOKENS = frozenset(
    {"const", "void", "unsigned", "signed", "int", "short", "char", "long",
     "float", "double", "bool", "undefined", "undefined1", "undefined2",
     "undefined4", "undefined8", "byte", "uint", "ushort"}
)


def _forward_decl_types(slots: list[ClassifiedSlot], skip: set[str]) -> list[str]:
    """Game/Ghidra class types referenced in slot signatures that need a forward
    declaration (the generated header only includes its base + game/mfc.h)."""
    names: set[str] = set()
    for s in slots:
        if s.kind not in ("override", "new") or s.sig is None:
            continue
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", f"{s.sig.ret} {s.sig.args}"):
            if tok in _PRIMITIVE_TOKENS or tok in skip:
                continue
            if _FWD_TYPE_RE.match(tok):
                names.add(tok)
    return sorted(names)


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
    # Skeleton only. The per-slot virtual declarations live in the single
    # `GENERATED DECLS` block that gen_class inserts after `public:`. `slots` is used
    # only to compute the forward declarations the DECLS signatures will need.
    fwd = _forward_decl_types(slots, skip={class_name, base_name})
    fwd_block = "\n".join(f"class {n};" for n in fwd)
    lines = [
        "#pragma once",
        "",
        base_header,
        # MFC/Windows types (CRuntimeClass, CString, CArchive, LONG, ...) used by the
        # generated virtual signatures; the lean base headers don't all pull these in.
        '#include "game/mfc.h"',
        "",
    ]
    if fwd_block:
        lines += ["// Forward declarations for types referenced by generated signatures.",
                  fwd_block, ""]
    lines += [
        edge_comment,
        f"// VTABLE: IMPERIALISM {vtable_addr}",
        f"class {class_name} : public {base_name} {{",
        "public:",
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


def render_cpp(class_name: str, slots: list[ClassifiedSlot], emit_markers: bool = True) -> str:
    """Render the class's .cpp.

    With ``emit_markers`` (the default, body-porting flow) each owned slot gets a
    ``// FUNCTION:`` marker, a Ghidra-seeded body, and an ownership/symbols claim.

    With ``emit_markers=False`` (the shape-only ``--no-bodies`` flow) the slots are
    emitted as plain *unmarked* out-of-line stubs: distinct C++ method symbols that
    give MSVC a key function so the class's vtable is emitted, but with **no**
    ``// FUNCTION:``/``// SYNTHETIC:`` markers and no ownership — claiming addresses is
    part of body porting, which is deferred, and the slot targets are heavily shared
    across classes (so claiming them would collide). Bodies + markers + ownership are
    added later, per class, by the real decomp loop.
    """
    lines = [f'#include "game/{class_name}.h"', ""]
    if emit_markers:
        # RTTI class descriptor placeholder (see GetRuntimeClass). Omitted in
        # shape-only output: the stub GetRuntimeClass returns 0 (never references it),
        # and emitting it collides with descriptors hand-defined elsewhere (e.g.
        # CArchive.cpp) and mistypes headers that declare it as CRuntimeClass.
        lines += [
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
            if emit_markers:
                # The SYNTHETIC marker claims the compiler-generated scalar deleting
                # destructor (??_G) for reccmp; the empty `~Class() {}` gives MSVC a
                # real base destructor so the polymorphic vtable links.
                lines.append(f"// SYNTHETIC: IMPERIALISM 0x{s.target_addr}")
                lines.append(f"// {class_name}::`scalar deleting destructor'")
            lines.append(f"{class_name}::~{class_name}() {{}}")
            lines.append("")
            continue
        assert s.sig is not None
        if emit_markers:
            lines.append(f"// FUNCTION: IMPERIALISM 0x{s.target_addr}")
            lines.append(f"{s.sig.definition_head(class_name)} {{")
            lines += _body_seed(s)
            lines.append("}")
        else:
            # Unmarked shape-only stub: compiles + emits the vtable, claims nothing.
            ret = s.sig.ret.strip()
            body = " return 0; " if ret not in ("void", "") else ""
            lines.append(f"{s.sig.definition_head(class_name)} {{{body}}}")
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
    updated_rows: list[str] = field(default_factory=list)
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
    by_addr = {norm_addr(r.get("address", "")): r for r in rows}
    for s in owned:
        target_addr = norm_addr(s.target_addr)
        if not target_addr:
            continue
        if s.kind == "scalar_dtor":
            name = f"{class_name}::`scalar deleting destructor'"
            proto = "undefined ScalarDeletingDestructor()"
            existing = by_addr.get(target_addr)
            if existing is not None:
                changed = False
                if (existing.get("name") or "") != name:
                    existing["name"] = name
                    changed = True
                if (existing.get("type") or "") != "function":
                    existing["type"] = "function"
                    changed = True
                if (existing.get("prototype") or "") != proto:
                    existing["prototype"] = proto
                    changed = True
                if changed:
                    plan.updated_rows.append(target_addr)
                continue
        else:
            assert s.sig is not None
            name = f"{class_name}::{s.sig.name}"
            proto = s.prototype or f"{s.sig.ret} {s.sig.name}({s.sig.args})"
            existing = by_addr.get(target_addr)
            if existing is not None:
                changed = False
                if (existing.get("name") or "") != name:
                    existing["name"] = name
                    changed = True
                if (existing.get("type") or "") != "function":
                    existing["type"] = "function"
                    changed = True
                if proto and (existing.get("prototype") or "") != proto:
                    existing["prototype"] = proto
                    changed = True
                if changed:
                    plan.updated_rows.append(target_addr)
                continue
        plan.new_rows.append(
            {
                "address": target_addr,
                "name": name,
                "size": str(s.size or 1),
                "type": "function",
                "prototype": proto,
            }
        )
        by_addr[target_addr] = plan.new_rows[-1]
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


_GEN_BLOCK_RE = re.compile(
    r"// === BEGIN GENERATED(?: DECLS)? \([^)]*\) .*?// === END GENERATED(?: DECLS)? \([^)]*\) ===",
    re.DOTALL,
)
_MEMBER_DECL_RE = re.compile(r"(~?[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_DECL_LINE_NAME_RE = re.compile(r"(~?[A-Za-z_][A-Za-z0-9_]*)\s*\(")


def drop_externally_declared_declarations(decls: str, header_text: str, cls: str) -> str:
    """Remove generated-DECLS lines whose member is already declared outside GENERATED blocks."""
    outside = _GEN_BLOCK_RE.sub("", header_text)
    external: set[str] = set()
    for line in outside.splitlines():
        s = line.strip()
        if not s or s.startswith("//") or "(" not in s:
            continue
        if "=" in s.split("(", 1)[0]:
            continue
        m = _MEMBER_DECL_RE.search(s)
        if m:
            external.add(m.group(1))
    if not external:
        return decls
    kept: list[str] = []
    for line in decls.splitlines():
        stripped = line.strip()
        if stripped.startswith("virtual "):
            m = _DECL_LINE_NAME_RE.search(stripped)
            name = m.group(1) if m else ""
            if name in external or (name == f"~{cls}" and f"~{cls}" in external):
                continue
        kept.append(line)
    return "\n".join(kept)
