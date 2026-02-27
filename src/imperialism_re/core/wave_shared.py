from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.datatypes import find_named_data_type


def sanitize_symbol_name(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", text)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        return "UnknownTarget"
    if s[0].isdigit():
        s = "_" + s
    return s


def is_unresolved_name(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )


def is_generic_strict_callee(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )


def split_pointer_type(type_name: str) -> tuple[str, int]:
    t = type_name.strip().replace(" ", "")
    stars = 0
    while t.endswith("*"):
        stars += 1
        t = t[:-1]
    return t, stars


def normalize_base_type_name(name: str) -> str:
    t = name.strip()
    t = t.replace("const ", "").replace("volatile ", "")
    t = t.replace("struct ", "").replace("class ", "")
    return t.strip()


@lru_cache(maxsize=2048)
def resolve_named_data_type(dtm, base_name: str):
    return find_named_data_type(dtm, base_name)


def build_data_type(type_name: str, dtm=None):
    from ghidra.program.model.data import (
        BooleanDataType,
        ByteDataType,
        CharDataType,
        IntegerDataType,
        PointerDataType,
        ShortDataType,
        UnsignedIntegerDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

    base_name, ptr_depth = split_pointer_type(type_name)
    base_name = normalize_base_type_name(base_name)
    base_key = base_name.lower()
    base_map = {
        "void": VoidDataType.dataType,
        "byte": ByteDataType.dataType,
        "char": CharDataType.dataType,
        "short": ShortDataType.dataType,
        "ushort": UnsignedShortDataType.dataType,
        "int": IntegerDataType.dataType,
        "uint": UnsignedIntegerDataType.dataType,
        "bool": BooleanDataType.dataType,
    }
    dt = base_map.get(base_key)
    if dt is None and dtm is not None:
        dt = resolve_named_data_type(dtm, base_name)
    if dt is None:
        dt = VoidDataType.dataType if ptr_depth > 0 else IntegerDataType.dataType
    for _ in range(ptr_depth):
        dt = PointerDataType(dt)
    return dt


def parse_params(raw: str):
    out: list[tuple[str, str]] = []
    txt = (raw or "").strip()
    if not txt:
        return out
    for part in txt.split(";"):
        p = part.strip()
        if not p:
            continue
        if ":" not in p:
            raise ValueError(f"invalid param entry (expected name:type): {p}")
        name, typ = p.split(":", 1)
        out.append((name.strip(), typ.strip()))
    return out


def single_jmp_to_target(listing, func, target_addr) -> bool:
    ins_it = listing.getInstructions(func.getBody(), True)
    ins = []
    while ins_it.hasNext():
        ins.append(ins_it.next())
        if len(ins) > 2:
            break
    if len(ins) != 1:
        return False
    if str(ins[0].getMnemonicString()).upper() != "JMP":
        return False
    flows = ins[0].getFlows()
    if flows is None or len(flows) != 1:
        return False
    return flows[0] == target_addr


def ensure_unique_name(existing_names: set[str], desired: str, fallback_suffix_addr: int) -> str:
    if desired not in existing_names:
        return desired
    base = f"{desired}_At{fallback_suffix_addr:08x}"
    cur = base
    i = 2
    while cur in existing_names:
        cur = f"{base}_{i}"
        i += 1
    return cur


def write_dict_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]):
    write_csv_rows(path, rows, fieldnames)


def build_unresolved_rows(program, lo: int, hi: int, name_regex: str) -> list[dict[str, str]]:
    fm = program.getFunctionManager()
    rm = program.getReferenceManager()
    listing = program.getListing()
    af = program.getAddressFactory().getDefaultAddressSpace()
    name_re = re.compile(name_regex)

    rows: list[dict[str, str]] = []
    fit = fm.getFunctions(True)
    while fit.hasNext():
        f = fit.next()
        addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
        if addr < lo or addr > hi:
            continue
        name = f.getName()
        if not name_re.search(name):
            continue

        refs_to = rm.getReferencesTo(af.getAddress(f"0x{addr:08x}"))
        callers_named = 0
        callers_generic = 0
        callers_total = 0
        callers_set = set()
        for ref in refs_to:
            c = fm.getFunctionContaining(ref.getFromAddress())
            if c is None:
                continue
            caddr = c.getEntryPoint().getOffset() & 0xFFFFFFFF
            key = (caddr, c.getName())
            if key in callers_set:
                continue
            callers_set.add(key)
            callers_total += 1
            if is_unresolved_name(c.getName()):
                callers_generic += 1
            else:
                callers_named += 1

        instr_count = 0
        call_insn_count = 0
        callee_named = set()
        callee_generic = set()
        ins_it = listing.getInstructions(f.getBody(), True)
        while ins_it.hasNext():
            ins = ins_it.next()
            instr_count += 1
            if str(ins.getMnemonicString()).upper() != "CALL":
                continue
            call_insn_count += 1
            for ref in ins.getReferencesFrom():
                c = fm.getFunctionAt(ref.getToAddress())
                if c is None:
                    continue
                caddr_txt = str(c.getEntryPoint())
                if caddr_txt.startswith("EXTERNAL:"):
                    continue
                ctag = f"{c.getName()}@{caddr_txt}"
                if is_unresolved_name(c.getName()):
                    callee_generic.add(ctag)
                else:
                    callee_named.add(ctag)

        ns = f.getParentNamespace()
        rows.append(
            {
                "address": f"0x{addr:08x}",
                "name": name,
                "namespace": "" if ns is None else ns.getName(),
                "instruction_count": str(instr_count),
                "call_insn_count": str(call_insn_count),
                "xrefs_to_count": str(callers_total),
                "named_caller_count": str(callers_named),
                "generic_caller_count": str(callers_generic),
                "named_callee_count": str(len(callee_named)),
                "generic_callee_count": str(len(callee_generic)),
                "named_callees": ";".join(sorted(callee_named)),
                "sample_callers": ";".join(
                    sorted(f"{nm}@0x{ca:08x}" for ca, nm in callers_set)[:12]
                ),
            }
        )

    rows.sort(
        key=lambda r: (
            -int(r["named_caller_count"]),
            -int(r["xrefs_to_count"]),
            -int(r["named_callee_count"]),
            r["address"],
        )
    )
    return rows


def build_strict_gate_rows(program, caller_regex: str) -> list[dict[str, str]]:
    fm = program.getFunctionManager()
    listing = program.getListing()
    cre = re.compile(caller_regex)
    rows: list[dict[str, str]] = []

    fit = fm.getFunctions(True)
    while fit.hasNext():
        caller = fit.next()
        caller_name = caller.getName()
        if not cre.search(caller_name):
            continue

        generic: set[str] = set()
        ins_it = listing.getInstructions(caller.getBody(), True)
        while ins_it.hasNext():
            ins = ins_it.next()
            if not str(ins).startswith("CALL "):
                continue
            for ref in ins.getReferencesFrom():
                callee = fm.getFunctionAt(ref.getToAddress())
                if callee is None:
                    continue
                callee_name = callee.getName()
                if is_generic_strict_callee(callee_name):
                    generic.add(f"{callee_name}@{callee.getEntryPoint()}")

        if generic:
            rows.append(
                {
                    "caller_addr": str(caller.getEntryPoint()),
                    "caller_name": caller_name,
                    "generic_callee_count": str(len(generic)),
                    "generic_callees": ";".join(sorted(generic)),
                }
            )

    rows.sort(key=lambda r: (-int(r["generic_callee_count"]), r["caller_name"]))
    return rows


def compute_progress(program) -> dict[str, int]:
    fm = program.getFunctionManager()
    st = program.getSymbolTable()
    rx_default = re.compile(r"^(FUN_|thunk_FUN_)")

    total = renamed = default_named = 0
    fit = fm.getFunctions(True)
    while fit.hasNext():
        f = fit.next()
        total += 1
        if rx_default.match(f.getName()):
            default_named += 1
        else:
            renamed += 1

    class_desc = vtbl = tname = 0
    sit = st.getAllSymbols(True)
    while sit.hasNext():
        n = sit.next().getName()
        if n.startswith("g_pClassDescT"):
            class_desc += 1
        if n.startswith("g_vtblT"):
            if "_Slot" in n or "Candidate_" in n or "Family_" in n:
                continue
            vtbl += 1
        if n.startswith("g_szTypeNameT"):
            tname += 1

    return {
        "total_functions": total,
        "renamed_functions": renamed,
        "default_fun_or_thunk_fun": default_named,
        "class_desc_count": class_desc,
        "vtbl_count": vtbl,
        "type_name_count": tname,
    }
