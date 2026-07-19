#!/usr/bin/env python3
"""Read-only: cross-check `no_rtti` class-model records against independent
original-binary evidence (the 408 `CRuntimeClass`-evidenced records are already
size-verified by `tools/class_model_audit.py`; `no_rtti` records are projected
from source + the MSVC500 layout oracle only, with no CRuntimeClass to check
against).

For each `no_rtti` class this tool gathers, from the live Ghidra DB:

  - **operator_new_exact** — a known constructor's callers are decompiled and
    scanned for an `operator_new(0xNN)` allocation immediately feeding that
    ctor's `this` — the strongest, most direct evidence (the original
    allocation site proves the real object size).
  - **ctor_dtor_max_offset** — the constructor/destructor bodies (when a real
    address is known) are decompiled and scanned for the highest `this`-relative
    byte offset accessed — a LOWER bound only (the object could be larger; nothing
    proves there's not more state after the last field the ctor happens to touch).
  - **derived_zero_own_fields_exact** — when another class derives from this one
    at offset 0, adds NO fields of its own (per the layout oracle), and the
    derived class's own operator_new size is known, that number is this base's
    exact size too (the derived object's whole layout LEQ2 this base's layout).
  - **external_sdk_header** — a small curated table of well-known Win32/DirectX
    struct sizes (DSBCAPS, DSBUFFERDESC, ...), cited as a named oracle per the
    task's "named external oracle" allowance.

None of these evidence collectors write anything: the tool only opens the
Ghidra project read-only and only ever reads/decompiles.

Classification (`classify_no_rtti_record`) is a pure function over plain
evidence dicts — unit-testable independent of a live Ghidra program — that
maps evidence to exactly one of:

  binary_size_verified    — exact evidence matches the source/oracle size
  binary_lower_bound_only — a lower bound was found, consistent with the
                             source size (could still be larger)
  binary_upper_bound_only — an upper bound was found (e.g. a following field
                             or sibling allocation caps it), consistent with
                             the source size
  no_binary_size_evidence — nothing found; NOT a block, just unverified
  source_binary_contradiction — real binary evidence DISAGREES with the
                             source/oracle size (source is either too small
                             for evidence found inside it, or provably
                             mismatched against an exact allocation site)

Writes build-msvc500/evidence/no_rtti_class_audit.csv with columns:
  class, source_size, base_size, evidence_kind, evidence_address,
  binary_size_or_bound, verdict, notes

Usage:
  uv run python -m tools.ghidra.no_rtti_class_audit
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows

# --------------------------------------------------------------------------- #
# Pure classification core — no Ghidra dependency, fully unit-testable.
# --------------------------------------------------------------------------- #

# Evidence "strength" order: exact evidence beats bounds beats nothing.
_EXACT_KINDS = {"operator_new_exact", "derived_zero_own_fields_exact", "external_sdk_header"}
_LOWER_BOUND_KINDS = {"ctor_dtor_max_offset"}
_UPPER_BOUND_KINDS = {"upper_bound_from_sibling"}


def classify_no_rtti_record(source_size: int, evidences: list[dict]) -> tuple[str, str]:
    """Classify one no_rtti class from its oracle-computed `source_size` and a
    list of evidence dicts, each `{"kind": str, "value": int, "address": str,
    "note": str}`. Returns (verdict, notes) — notes is a "; "-joined summary of
    every evidence item considered, so the CSV row is self-explanatory even when
    several evidence collectors ran.

    `value` for an exact kind is the observed real size; for
    `ctor_dtor_max_offset` it is the highest observed (offset + width), i.e. the
    minimum size the class must be; for `upper_bound_from_sibling` it is the
    highest size the class could be.
    """
    if not evidences:
        return "no_binary_size_evidence", "no original-binary evidence found"

    notes: list[str] = []
    exact_values: set[int] = set()
    lower_bounds: list[int] = []
    upper_bounds: list[int] = []

    for ev in evidences:
        kind = ev["kind"]
        value = ev["value"]
        addr = ev.get("address", "")
        note = ev.get("note", "")
        tag = f"{kind}={value:#x}" + (f"@{addr}" if addr else "") + (f" ({note})" if note else "")
        notes.append(tag)
        if kind in _EXACT_KINDS:
            exact_values.add(value)
        elif kind in _LOWER_BOUND_KINDS:
            lower_bounds.append(value)
        elif kind in _UPPER_BOUND_KINDS:
            upper_bounds.append(value)

    joined = "; ".join(notes)

    if exact_values:
        if len(exact_values) > 1:
            # Two independent exact-evidence sources disagree with each other —
            # a genuine contradiction regardless of what source_size says.
            return "source_binary_contradiction", (
                f"conflicting exact evidence {sorted(hex(v) for v in exact_values)}: {joined}"
            )
        exact = next(iter(exact_values))
        if exact != source_size:
            return "source_binary_contradiction", (
                f"exact binary evidence {exact:#x} != source/oracle size {source_size:#x}: {joined}"
            )
        return "binary_size_verified", joined

    max_lower = max(lower_bounds) if lower_bounds else None
    if max_lower is not None and max_lower > source_size:
        return "source_binary_contradiction", (
            f"ctor/dtor accesses offset {max_lower:#x} beyond source size {source_size:#x}: {joined}"
        )

    min_upper = min(upper_bounds) if upper_bounds else None
    if min_upper is not None and min_upper < source_size:
        return "source_binary_contradiction", (
            f"upper bound {min_upper:#x} is smaller than source size {source_size:#x}: {joined}"
        )

    if max_lower is not None:
        return "binary_lower_bound_only", joined
    if min_upper is not None:
        return "binary_upper_bound_only", joined
    return "no_binary_size_evidence", joined


# --------------------------------------------------------------------------- #
# Curated external-SDK oracle (named, not address-based evidence).
# --------------------------------------------------------------------------- #

# Well-known Win32/DirectX struct sizes on x86 (4-byte alignment, no padding
# beyond natural alignment for these particular structs) — cited as a named
# external oracle per the task's "address or named external oracle" allowance.
_EXTERNAL_SDK_SIZES: dict[str, tuple[int, str]] = {
    "DSBCAPS": (0x14, "DirectSound 5 SDK dsound.h: DSBCAPS is {dwSize,dwFlags,dwBufferBytes,"
                       "dwUnlockTransferRate,dwPlayCpuOverhead} = 5 DWORDs"),
    "DSBUFFERDESC": (0x14, "DirectSound 5 SDK dsound.h: DSBUFFERDESC is {dwSize,dwFlags,"
                           "dwBufferBytes,dwReserved,lpwfxFormat} = 5 DWORDs"),
    "IDirectSound": (0x4, "COM interface pointer (vtable ptr only) — DirectSound 5 SDK dsound.h"),
    "IDirectSoundBuffer": (0x4, "COM interface pointer (vtable ptr only) — DirectSound 5 SDK dsound.h"),
}


# --------------------------------------------------------------------------- #
# Source-side ctor/dtor address discovery (no Ghidra needed).
# --------------------------------------------------------------------------- #

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{4,8}")


def find_known_addrs(repo: Path, class_name: str) -> list[tuple[str, str, str]]:
    """Discover known ctor/dtor addresses for `class_name` from three sources:
    `config/original_entities.csv`, `config/symbols.ghidra.txt`, and anchored
    ctor/dtor declaration/definition lines under `include/`/`src/`. Returns a
    deduped list of (address, symbol_or_context, location) tuples.

    Anchored means the class name must appear at the START of the declaration
    (`^\\s*ClassName\\s*\\(` / `^\\s*~ClassName\\s*\\(`) or as a qualified
    `ClassName::ClassName(` / `ClassName::~ClassName(` definition — a bare
    substring match (e.g. a function parameter of type `OrderSheet*`, or a
    method named `...Region(...)`) must NOT match.
    """
    simple = class_name.split("::")[-1]
    seen: set[str] = set()
    out: list[tuple[str, str, str]] = []

    def add(addr: str, symbol: str, location: str) -> None:
        addr = addr.lower()
        if not addr.startswith("0x"):
            addr = "0x" + addr
        if addr not in seen:
            seen.add(addr)
            out.append((addr, symbol, location))

    entities_path = repo / "config/original_entities.csv"
    if entities_path.exists():
        for row in read_pipe_rows(entities_path):
            addr, symname = row.get("address", ""), row.get("name", "")
            if symname in (f"{simple}::{simple}", f"{simple}::~{simple}"):
                add(addr, symname, "config/original_entities.csv")

    symbols_path = repo / "config/symbols.ghidra.txt"
    if symbols_path.exists():
        for line in symbols_path.read_text(errors="ignore").splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            symname, addr = parts[0], parts[1]
            if symname in (f"{simple}::{simple}", f"{simple}::~{simple}"):
                add(addr, symname, "config/symbols.ghidra.txt")

    ctor_line_re = re.compile(rf"^\s*(?:explicit\s+)?{re.escape(simple)}\s*\(")
    dtor_line_re = re.compile(rf"^\s*(?:virtual\s+)?~{re.escape(simple)}\s*\(")
    def_ctor_re = re.compile(rf"{re.escape(simple)}::{re.escape(simple)}\s*\(")
    def_dtor_re = re.compile(rf"{re.escape(simple)}::~{re.escape(simple)}\s*\(")

    for base_dir, pattern in (("include", "*.h"), ("src", "*.cpp")):
        root = repo / base_dir
        if not root.exists():
            continue
        for path in root.rglob(pattern):
            try:
                lines = path.read_text(errors="ignore").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                if (ctor_line_re.match(line) or dtor_line_re.match(line)) and "//" in line:
                    m = _ADDR_RE.search(line.split("//", 1)[1])
                    if m:
                        add(m.group(0), f"{simple} decl", f"{path}:{i + 1}")
                if def_ctor_re.search(line) or def_dtor_re.search(line):
                    for j in range(max(0, i - 3), i):
                        m = re.search(
                            r"(?:FUNCTION|SYNTHETIC):\s*IMPERIALISM\s*(0x[0-9a-fA-F]+)", lines[j]
                        )
                        if m:
                            add(m.group(1), f"{simple} def marker", f"{path}:{j + 1}")
    return out


# --------------------------------------------------------------------------- #
# Ghidra-side evidence collection (read-only).
# --------------------------------------------------------------------------- #

_FIELD_OFFSET_RE = re.compile(r"->field_0x([0-9a-fA-F]+)")
_RAW_OFFSET_RE = re.compile(r"\(int\)this \+ 0x([0-9a-fA-F]+)\)")
_OPERATOR_NEW_RE = re.compile(r"operator_new\(0x([0-9a-fA-F]+)\)")
# Captures the assigned variable, e.g. `pTVar4 = (Foo *)operator_new(0x14);` or
# the no-cast form `pTVar4 = operator_new(0x14);`.
_OPERATOR_NEW_ASSIGN_RE = re.compile(
    r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?operator_new\(0x([0-9a-fA-F]+)\)"
)


def _is_jump_thunk(program, from_addr) -> bool:
    listing = program.getListing()
    ins = listing.getInstructionAt(from_addr)
    if ins is None:
        return False
    if ins.getMnemonicString().lower() != "jmp":
        return False
    fn = program.getFunctionManager().getFunctionContaining(from_addr)
    return fn is None or bool(fn.isThunk())


def _callers_of(program, addr_int: int, limit: int = 8):
    """Functions that (directly, or via one ILT-thunk hop) call `addr_int`."""
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    rm = program.getReferenceManager()
    addr = af.getAddress(addr_int)
    callers = []
    n = 0
    for ref in rm.getReferencesTo(addr):
        if n >= limit:
            break
        frm = ref.getFromAddress()
        if _is_jump_thunk(program, frm):
            for inner in rm.getReferencesTo(frm):
                if n >= limit:
                    break
                fn = fm.getFunctionContaining(inner.getFromAddress())
                if fn is not None:
                    callers.append(fn)
                    n += 1
            continue
        fn = fm.getFunctionContaining(frm)
        if fn is not None:
            callers.append(fn)
            n += 1
    return callers


_MAX_DECOMPILE_BODY_BYTES = 4000


def _decompile(ifc, fn, monitor) -> str | None:
    # A handful of caller functions in this binary are enormous (dispatch tables,
    # giant switch statements); decompiling them can burn tens of seconds each,
    # which adds up fast across dozens of no_rtti classes. This is a heuristic
    # evidence scan, not a definitive one, so skip bodies too big to be worth it.
    if fn.getBody().getNumAddresses() > _MAX_DECOMPILE_BODY_BYTES:
        return None
    res = ifc.decompileFunction(fn, 10, monitor)
    if not res.decompileCompleted():
        return None
    return res.getDecompiledFunction().getC()


_MAX_NEW_TO_CTOR_GAP_CHARS = 400


def find_operator_new_feeding_ctor(text: str, ctor_name: str) -> int | None:
    """Pure text-scan core of the operator_new evidence collector (unit-testable
    independent of a live Ghidra decompile). A caller function can construct
    several unrelated objects (e.g. a UI factory that builds one control and
    also allocates an unrelated string/buffer, or several objects of different
    types before running any of their constructors); naively matching the
    nearest preceding `operator_new` by TEXT PROXIMITY alone conflates those.
    This requires the SAME variable assigned by `operator_new` to also be the
    ctor call's first (`this`) argument, and rejects the pairing if it's
    implausibly far apart in the text. Returns the matched size, or None if no
    qualifying pairing exists."""
    ctor_call_re = re.compile(re.escape(ctor_name) + r"\s*\(\s*(\w+)")
    assignments = list(_OPERATOR_NEW_ASSIGN_RE.finditer(text))
    for ctor_match in ctor_call_re.finditer(text):
        this_arg = ctor_match.group(1)
        # The nearest PRECEDING assignment of this same variable from operator_new.
        candidates = [
            m for m in assignments
            if m.group(1) == this_arg and m.end() <= ctor_match.start()
        ]
        if not candidates:
            continue
        best = candidates[-1]
        if ctor_match.start() - best.end() > _MAX_NEW_TO_CTOR_GAP_CHARS:
            continue  # too far apart to trust the pairing
        return int(best.group(2), 16)
    return None


def collect_operator_new_evidence(program, ifc, monitor, ctor_addr: int) -> dict | None:
    """Decompile every caller of `ctor_addr` and look for an `operator_new(0xNN)`
    call that directly feeds a call to this specific constructor (see
    `find_operator_new_feeding_ctor`). Returns the first qualifying match found
    (an evidence dict) or None."""
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    ctor_fn = fm.getFunctionContaining(af.getAddress(ctor_addr))
    ctor_name = ctor_fn.getName() if ctor_fn is not None else None
    if not ctor_name:
        return None
    for caller in _callers_of(program, ctor_addr):
        text = _decompile(ifc, caller, monitor)
        if not text:
            continue
        value = find_operator_new_feeding_ctor(text, ctor_name)
        if value is not None:
            return {
                "kind": "operator_new_exact",
                "value": value,
                "address": f"0x{caller.getEntryPoint().getOffset():08x}",
                "note": f"operator_new directly feeding {ctor_name} in caller {caller.getName()}",
            }
    return None


def collect_ctor_dtor_offset_evidence(program, ifc, monitor, addr_int: int) -> dict | None:
    """Decompile the function at `addr_int` (a ctor or dtor) and find the
    highest `this`-relative byte offset it accesses. Returns a
    ctor_dtor_max_offset evidence dict (value = offset + inferred width) or
    None if no offset access is found."""
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    fn = fm.getFunctionContaining(af.getAddress(addr_int))
    if fn is None:
        return None
    text = _decompile(ifc, fn, monitor)
    if not text:
        return None
    max_end = 0
    for m in _FIELD_OFFSET_RE.finditer(text):
        off = int(m.group(1), 16)
        # Assume at least a 1-byte access; widen to 4 for the common
        # `*(undefined4 *)&this->field_0xNN` pattern seen right before the match.
        prefix = text[max(0, m.start() - 24) : m.start()]
        width = 4 if "undefined4" in prefix or "int *" in prefix else 1
        max_end = max(max_end, off + width)
    for m in _RAW_OFFSET_RE.finditer(text):
        off = int(m.group(1), 16)
        max_end = max(max_end, off + 1)
    if max_end == 0:
        return None
    return {
        "kind": "ctor_dtor_max_offset",
        "value": max_end,
        "address": f"0x{addr_int:08x}",
        "note": f"max this-relative access in {fn.getName()}",
    }


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def load_no_rtti_classes(repo: Path) -> list[tuple[str, int]]:
    """Returns [(class_name, source_size)] for every no_rtti row."""
    out = []
    audit_path = repo / "build-msvc500/evidence/class_model_audit.csv"
    with open(audit_path, newline="") as fh:
        for row in csv.DictReader(fh):
            if row["verdict"] != "no_rtti":
                continue
            size_s = (row.get("oracle_size") or "").strip()
            if not size_s:
                continue
            out.append((row["name"], int(size_s, 16)))
    return out


def load_layout_bases(repo: Path) -> dict:
    layout = json.loads((repo / "build-msvc500/generated/layout_oracle.json").read_text())
    return layout["layouts"]


def find_zero_field_derived(layouts: dict, base_name: str) -> list[str]:
    """Classes that derive from `base_name` at offset 0 and add no fields of
    their own — a size proof for one transfers exactly to the other."""
    out = []
    for cname, lay in layouts.items():
        bases = lay.get("bases", {})
        if bases.get(base_name) == 0 and not lay.get("fields"):
            out.append(cname)
    return out


def run(program, repo: Path, verbose: bool = False) -> list[dict]:
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor

    classes = load_no_rtti_classes(repo)
    layouts = load_layout_bases(repo)

    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.setSimplificationStyle("decompile")
    if not ifc.openProgram(program):
        raise RuntimeError(f"openProgram failed: {ifc.getLastMessage()}")
    monitor = ConsoleTaskMonitor()

    rows = []
    try:
        # Pass 1: gather direct evidence (operator_new + ctor/dtor offsets) per class.
        direct_evidence: dict[str, list[dict]] = {}
        addr_map: dict[str, list[tuple[str, str, str]]] = {}
        for name, _size in classes:
            addrs = find_known_addrs(repo, name)
            addr_map[name] = addrs
            evs: list[dict] = []
            seen_ctor_name_hits: set[int] = set()
            for addr_s, symbol, _loc in addrs:
                addr_int = int(addr_s, 16)
                is_ctor = symbol.endswith(f"::{name.split('::')[-1]}") or "decl" in symbol
                if is_ctor and addr_int not in seen_ctor_name_hits:
                    seen_ctor_name_hits.add(addr_int)
                    ev = collect_operator_new_evidence(program, ifc, monitor, addr_int)
                    if ev:
                        evs.append(ev)
                off_ev = collect_ctor_dtor_offset_evidence(program, ifc, monitor, addr_int)
                if off_ev:
                    evs.append(off_ev)
            if name in _EXTERNAL_SDK_SIZES:
                size, note = _EXTERNAL_SDK_SIZES[name]
                evs.append({"kind": "external_sdk_header", "value": size, "address": "", "note": note})
            direct_evidence[name] = evs
            if verbose:
                print(f"  {name}: {len(addrs)} addr(s), {len(evs)} direct evidence item(s)")

        # Pass 2: propagate derived_zero_own_fields_exact from any class whose
        # direct evidence resolved to an exact value onto its zero-own-field bases.
        exact_by_class: dict[str, int] = {}
        for name, evs in direct_evidence.items():
            for ev in evs:
                if ev["kind"] in _EXACT_KINDS:
                    exact_by_class[name] = ev["value"]
                    break

        for base_name, _size in classes:
            for derived in find_zero_field_derived(layouts, base_name):
                if derived in exact_by_class:
                    direct_evidence.setdefault(base_name, []).append({
                        "kind": "derived_zero_own_fields_exact",
                        "value": exact_by_class[derived],
                        "address": "",
                        "note": f"{derived} derives at offset 0 with zero own fields, "
                                f"exact size {exact_by_class[derived]:#x}",
                    })

        for name, source_size in classes:
            bases = layouts.get(name, {}).get("bases", {})
            base_size = ""
            if bases:
                first_base = next(iter(bases))
                base_layout = layouts.get(first_base)
                if base_layout is not None:
                    base_size = f"0x{base_layout['size']:x}"
            verdict, notes = classify_no_rtti_record(source_size, direct_evidence.get(name, []))
            evs = direct_evidence.get(name, [])
            primary = evs[0] if evs else None
            rows.append({
                "class": name,
                "source_size": f"0x{source_size:x}",
                "base_size": base_size,
                "evidence_kind": primary["kind"] if primary else "",
                "evidence_address": primary.get("address", "") if primary else "",
                "binary_size_or_bound": f"0x{primary['value']:x}" if primary else "",
                "verdict": verdict,
                "notes": notes,
            })
    finally:
        ifc.dispose()
    return rows


def main() -> int:
    from tools.common import ghidra_env
    from tools.common.repo import repo_root_from_file

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="build-msvc500/evidence/no_rtti_class_audit.csv")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    repo = repo_root_from_file(__file__, levels_up=2)
    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        rows = run(program, repo, verbose=args.verbose)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    out = repo / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "class", "source_size", "base_size", "evidence_kind", "evidence_address",
        "binary_size_or_bound", "verdict", "notes",
    ]
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    print(f"Wrote {len(rows)} rows to {out}")
    print("  " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    contradictions = [r["class"] for r in rows if r["verdict"] == "source_binary_contradiction"]
    if contradictions:
        print(f"CONTRADICTIONS ({len(contradictions)}): {', '.join(contradictions)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
