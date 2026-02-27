#!/usr/bin/env python3
"""
Extract enum candidate constants from:
  1) decompiled parameter compare/switch patterns
  2) instruction-level PUSH immediate -> CALL sequences

Domain CSV columns:
  domain (required)
  enum_path (required)
  function_name_regex (optional, default: .*)
  param_name_regex (optional, default: command/state/mode selector names)
  addr_min (optional)
  addr_max (optional)
  value_list (optional; comma-separated literals: 0x64,101,'yako')
  cluster_key (optional)
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.enum_candidates import parse_optional_int_token
from imperialism_re.core.ghidra_session import open_program


GENERIC_PARAM_RE = r"(command|event|tag|state|mode|type|token|selector|id)$"
GENERIC_NAME_RE = re.compile(r"^(FUN_|thunk_FUN_|LAB_|DAT_|PTR_)", re.IGNORECASE)


@dataclass
class DomainSpec:
    domain: str
    enum_path: str
    function_name_re: re.Pattern[str]
    param_name_re: re.Pattern[str]
    addr_min: int | None
    addr_max: int | None
    value_list: set[int] | None
    cluster_key: str


def _parse_int_literal(token: str) -> int:
    txt = token.strip()
    if txt.startswith("'") and txt.endswith("'") and len(txt) == 6:
        body = txt[1:-1]
        return int.from_bytes(body.encode("ascii", errors="strict"), byteorder="little", signed=False)
    if txt.lower().startswith("0x"):
        return int(txt, 16)
    if re.fullmatch(r"\d+", txt):
        return int(txt, 10)
    if len(txt) == 4 and txt.isascii():
        return int.from_bytes(txt.encode("ascii", errors="strict"), byteorder="little", signed=False)
    raise ValueError(f"invalid literal: {token}")


def _load_domain_specs(path: Path) -> list[DomainSpec]:
    rows = list(csv.DictReader(path.open("r", encoding="utf-8", newline="")))
    specs: list[DomainSpec] = []
    for row in rows:
        domain = (row.get("domain") or "").strip()
        enum_path = (row.get("enum_path") or "").strip()
        if not domain or not enum_path:
            continue

        fn_rx = (row.get("function_name_regex") or ".*").strip() or ".*"
        param_rx = (row.get("param_name_regex") or GENERIC_PARAM_RE).strip() or GENERIC_PARAM_RE
        addr_min = parse_optional_int_token(row.get("addr_min"))
        addr_max = parse_optional_int_token(row.get("addr_max"))
        value_list_raw = (row.get("value_list") or "").strip()
        value_list: set[int] | None = None
        if value_list_raw:
            vals = set()
            for part in value_list_raw.split(","):
                p = part.strip()
                if not p:
                    continue
                vals.add(_parse_int_literal(p))
            value_list = vals if vals else None

        specs.append(
            DomainSpec(
                domain=domain,
                enum_path=enum_path,
                function_name_re=re.compile(fn_rx, re.IGNORECASE),
                param_name_re=re.compile(param_rx, re.IGNORECASE),
                addr_min=addr_min,
                addr_max=addr_max,
                value_list=value_list,
                cluster_key=(row.get("cluster_key") or "").strip(),
            )
        )
    return specs


def _first_named_callee(fn) -> str:
    try:
        callees = fn.getCalledFunctions(None)
    except Exception:
        return ""
    try:
        it = callees.iterator()
        while it.hasNext():
            callee = it.next()
            nm = callee.getName() or ""
            if nm and not GENERIC_NAME_RE.match(nm):
                return nm
    except Exception:
        return ""
    return ""


def _parse_num(text: str) -> int | None:
    t = text.strip()
    if not t:
        return None
    try:
        if len(t) == 6 and t.startswith("'") and t.endswith("'"):
            body = t[1:-1]
            return int.from_bytes(body.encode("ascii", errors="strict"), byteorder="little", signed=False)
        if t.lower().startswith("0x"):
            return int(t, 16)
        return int(t, 10)
    except Exception:
        return None


def _extract_param_constant_hits(code: str, param_name: str) -> list[tuple[int, str, str, int]]:
    out: list[tuple[int, str, str, int]] = []
    p = re.escape(param_name)
    lit = r"(0x[0-9a-fA-F]+|\d+|'[^']{4}')"

    # param OP constant
    re_a = re.compile(rf"\b{p}\b\s*(==|!=|<=|>=|<|>)\s*{lit}")
    # constant OP param
    re_b = re.compile(rf"{lit}\s*(==|!=|<=|>=|<|>)\s*\b{p}\b")

    for m in re_a.finditer(code):
        op = m.group(1)
        value = _parse_num(m.group(2))
        if value is None:
            continue
        et = "compare_eq" if op in {"==", "!="} else "compare_rel"
        es = 3 if et == "compare_eq" else 2
        out.append((value, et, op, es))

    for m in re_b.finditer(code):
        op = m.group(2)
        value = _parse_num(m.group(1))
        if value is None:
            continue
        et = "compare_eq" if op in {"==", "!="} else "compare_rel"
        es = 3 if et == "compare_eq" else 2
        out.append((value, et, op, es))

    if re.search(rf"switch\s*\(\s*{p}\s*\)", code):
        for m in re.finditer(rf"\bcase\s+{lit}\s*:", code):
            value = _parse_num(m.group(1))
            if value is None:
                continue
            out.append((value, "switch_case", "case", 4))

    return out


def _field_offset_from_name(field_name: str) -> int | None:
    m = re.fullmatch(r"field([0-9a-fA-F]+)", field_name.strip())
    if m:
        return int(m.group(1), 16)
    return None


def _build_struct_field_offset_map(dtm, struct_path: str) -> dict[str, int]:
    st = dtm.getDataType(struct_path)
    if st is None:
        return {}
    out: dict[str, int] = {}
    try:
        count = int(st.getNumComponents())
    except Exception:
        count = 0
    for i in range(count):
        try:
            comp = st.getComponent(i)
            name = (comp.getFieldName() or "").strip()
            if not name:
                continue
            out[name.lower()] = int(comp.getOffset())
        except Exception:
            continue
    return out


def _extract_this_field_constant_hits(code: str, field_name: str) -> list[tuple[int, str, str, int]]:
    out: list[tuple[int, str, str, int]] = []
    f = re.escape(field_name)
    lit = r"(0x[0-9a-fA-F]+|\d+|'[^']{4}')"

    re_a = re.compile(rf"\bthis->{f}\b\s*(==|!=|<=|>=|<|>)\s*{lit}")
    re_b = re.compile(rf"{lit}\s*(==|!=|<=|>=|<|>)\s*\bthis->{f}\b")

    for m in re_a.finditer(code):
        op = m.group(1)
        value = _parse_num(m.group(2))
        if value is None:
            continue
        et = "field_compare_eq" if op in {"==", "!="} else "field_compare_rel"
        es = 3 if et == "field_compare_eq" else 2
        out.append((value, et, op, es))

    for m in re_b.finditer(code):
        op = m.group(2)
        value = _parse_num(m.group(1))
        if value is None:
            continue
        et = "field_compare_eq" if op in {"==", "!="} else "field_compare_rel"
        es = 3 if et == "field_compare_eq" else 2
        out.append((value, et, op, es))

    return out


def _extract_push_call_hits(program, fn, *, max_lookahead: int = 8) -> list[tuple[int, str]]:
    from ghidra.program.model.scalar import Scalar

    listing = program.getListing()
    body = fn.getBody()
    insts = list(listing.getInstructions(body, True))
    out: list[tuple[int, str]] = []
    count = len(insts)
    for i, ins in enumerate(insts):
        try:
            if (ins.getMnemonicString() or "").upper() != "PUSH":
                continue
            objs = list(ins.getOpObjects(0))
            if len(objs) != 1:
                continue
            scalar = objs[0]
            if not isinstance(scalar, Scalar):
                continue
            value = int(scalar.getUnsignedValue() & 0xFFFFFFFF)
        except Exception:
            continue

        anchor = ""
        for j in range(i + 1, min(count, i + 1 + max_lookahead)):
            nxt = insts[j]
            try:
                mnem = (nxt.getMnemonicString() or "").upper()
            except Exception:
                continue
            if mnem.startswith("J") or mnem in {"RET", "RETN", "HLT"}:
                break
            if mnem == "CALL":
                try:
                    refs = list(nxt.getReferencesFrom())
                    if refs:
                        to_addr = refs[0].getToAddress()
                        if to_addr is not None:
                            f = program.getFunctionManager().getFunctionAt(to_addr)
                            if f is not None:
                                cname = f.getName() or ""
                                if cname and not GENERIC_NAME_RE.match(cname):
                                    anchor = cname
                except Exception:
                    pass
                out.append((value, anchor))
                break
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains-csv", required=True, help="Domain extraction definitions CSV")
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--addr-min", default="0x00400000")
    ap.add_argument("--addr-max", default="0x006fffff")
    ap.add_argument("--max-functions", type=int, default=0)
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)

    domains_csv = Path(args.domains_csv)
    if not domains_csv.is_absolute():
        domains_csv = root / domains_csv
    if not domains_csv.exists():
        print(f"[error] missing domains csv: {domains_csv}")
        return 1

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    specs = _load_domain_specs(domains_csv)
    if not specs:
        print(f"[error] no valid domain specs in {domains_csv}")
        return 1

    addr_min = int(str(args.addr_min), 0)
    addr_max = int(str(args.addr_max), 0)

    rows: list[dict[str, str]] = []
    scanned = decompiled = matched = 0

    with open_program(root) as program:
        from ghidra.app.decompiler import DecompInterface

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()

        ifc = DecompInterface()
        ifc.openProgram(program)

        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            faddr = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
            if faddr < addr_min or faddr > addr_max:
                continue

            scanned += 1
            if args.max_functions > 0 and scanned > args.max_functions:
                break

            name = fn.getName() or ""
            ns = fn.getParentNamespace()
            ns_name = "" if ns is None else ns.getName()

            matched_specs = []
            for spec in specs:
                if spec.addr_min is not None and faddr < spec.addr_min:
                    continue
                if spec.addr_max is not None and faddr > spec.addr_max:
                    continue
                if not spec.function_name_re.search(name):
                    continue
                matched_specs.append(spec)

            if not matched_specs:
                continue

            res = ifc.decompileFunction(fn, 20, None)
            if not res.decompileCompleted():
                continue
            decompiled += 1
            code = res.getDecompiledFunction().getC() or ""
            if not code:
                continue

            params = list(fn.getParameters())
            if not params:
                continue

            callee_anchor = _first_named_callee(fn)
            push_call_hits = _extract_push_call_hits(program, fn)
            seen = set()

            for spec in matched_specs:
                struct_path = ""
                struct_field_offsets: dict[str, int] = {}
                if ns_name and ns_name.lower() != "global":
                    struct_path = f"/imperialism/classes/{ns_name}"
                    struct_field_offsets = _build_struct_field_offset_map(dtm, struct_path)

                for p in params:
                    pname = str(p.getName() or "")
                    if not pname or not spec.param_name_re.search(pname):
                        continue
                    hits = _extract_param_constant_hits(code, pname)
                    for value, evidence_type, op, strength in hits:
                        if spec.value_list is not None and value not in spec.value_list:
                            continue
                        dedup_key = (spec.domain, spec.enum_path, pname.lower(), value, evidence_type, op)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        rows.append(
                            {
                                "domain": spec.domain,
                                "address": f"0x{faddr:08x}",
                                "function_addr": f"0x{faddr:08x}",
                                "function_name": name,
                                "namespace": ns_name,
                                "kind": "param_compare",
                                "param_name_or_field": pname,
                                "immediate_value": str(value),
                                "immediate_hex": f"0x{value:08x}",
                                "evidence_type": evidence_type,
                                "operator": op,
                                "evidence_strength": str(strength),
                                "cluster_key": spec.cluster_key or (ns_name or "Global"),
                                "callee_anchor": callee_anchor,
                                "enum_path": spec.enum_path,
                                "struct_path": "",
                                "offset_hex": "",
                                "field_name": "",
                            }
                        )
                        matched += 1

                # Optional struct field evidence lane for class methods.
                if struct_path:
                    field_names = set(struct_field_offsets.keys())
                    # Add synthetic field* names if they appear in decomp and aren't in struct metadata.
                    for m in re.finditer(r"\bthis->(field[0-9a-fA-F]+)\b", code):
                        field_names.add(m.group(1).lower())

                    for fname_l in sorted(field_names):
                        fname = fname_l
                        off = struct_field_offsets.get(fname_l)
                        if off is None:
                            off = _field_offset_from_name(fname)
                        if off is None:
                            continue
                        hits = _extract_this_field_constant_hits(code, fname)
                        for value, evidence_type, op, strength in hits:
                            if spec.value_list is not None and value not in spec.value_list:
                                continue
                            dedup_key = (
                                spec.domain,
                                spec.enum_path,
                                "struct_field",
                                struct_path,
                                off,
                                value,
                                evidence_type,
                                op,
                            )
                            if dedup_key in seen:
                                continue
                            seen.add(dedup_key)
                            rows.append(
                                {
                                    "domain": spec.domain,
                                    "address": f"0x{faddr:08x}",
                                    "function_addr": f"0x{faddr:08x}",
                                    "function_name": name,
                                    "namespace": ns_name,
                                    "kind": "struct_field",
                                    "param_name_or_field": f"{struct_path}+0x{off:x}",
                                    "immediate_value": str(value),
                                    "immediate_hex": f"0x{value:08x}",
                                    "evidence_type": evidence_type,
                                    "operator": op,
                                    "evidence_strength": str(strength),
                                    "cluster_key": spec.cluster_key or (ns_name or "Global"),
                                    "callee_anchor": callee_anchor,
                                    "enum_path": spec.enum_path,
                                    "struct_path": struct_path,
                                    "offset_hex": f"0x{off:x}",
                                    "field_name": fname,
                                }
                            )
                            matched += 1

                # Secondary evidence lane: PUSH imm followed by CALL.
                # This captures command-id style constants passed through indirect callbacks.
                if spec.value_list is None:
                    continue
                for value, call_anchor in push_call_hits:
                    if value not in spec.value_list:
                        continue
                    dedup_key = (
                        spec.domain,
                        spec.enum_path,
                        "push_call",
                        value,
                        call_anchor.lower(),
                    )
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    rows.append(
                        {
                            "domain": spec.domain,
                            "address": f"0x{faddr:08x}",
                            "function_addr": f"0x{faddr:08x}",
                            "function_name": name,
                            "namespace": ns_name,
                            "kind": "call_arg_immediate",
                            "param_name_or_field": "call_arg0",
                            "immediate_value": str(value),
                            "immediate_hex": f"0x{value:08x}",
                            "evidence_type": "push_call",
                            "operator": "push_call",
                            "evidence_strength": "3",
                            "cluster_key": spec.cluster_key or (ns_name or "Global"),
                            "callee_anchor": call_anchor or callee_anchor,
                            "enum_path": spec.enum_path,
                            "struct_path": "",
                            "offset_hex": "",
                            "field_name": "",
                        }
                    )
                    matched += 1

    fieldnames = [
        "domain",
        "address",
        "function_addr",
        "function_name",
        "namespace",
        "kind",
        "param_name_or_field",
        "immediate_value",
        "immediate_hex",
        "evidence_type",
        "operator",
        "evidence_strength",
        "cluster_key",
        "callee_anchor",
        "enum_path",
        "struct_path",
        "offset_hex",
        "field_name",
    ]
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=fieldnames)
        wr.writeheader()
        wr.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    print(f"[stats] specs={len(specs)} scanned={scanned} decompiled={decompiled} matched={matched}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
