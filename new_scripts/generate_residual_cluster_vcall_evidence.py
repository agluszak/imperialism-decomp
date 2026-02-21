#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import pyghidra


def log(msg: str):
    print(msg, flush=True)


def parse_hex_addr(s: str) -> int:
    s = s.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    return int(s, 16)


def is_exec_addr(program, addr):
    b = program.getMemory().getBlock(addr)
    return b is not None and b.isExecute()


def get_thunk_aliases(program, target_addr):
    """Find tiny thunk functions that jump/call to target_addr."""
    fm = program.getFunctionManager()
    listing = program.getListing()
    aliases = []
    it = fm.getFunctions(True)
    while it.hasNext():
        f = it.next()
        ep = f.getEntryPoint()
        if ep == target_addr:
            continue
        body_size = int(f.getBody().getNumAddresses())
        if body_size > 8:
            continue
        ins = listing.getInstructionAt(ep)
        if ins is None:
            continue
        m = ins.getMnemonicString().upper()
        if m not in ("JMP", "CALL"):
            continue
        flows = ins.getFlows()
        if flows is None or len(flows) != 1:
            continue
        if flows[0] == target_addr:
            aliases.append(f)
    return aliases


def collect_refs(program, addr):
    rm = program.getReferenceManager()
    fm = program.getFunctionManager()
    refs = rm.getReferencesTo(addr)
    code_callers = []
    data_refs = []
    seen_code = set()
    seen_data = set()
    for ref in refs:
        from_addr = ref.getFromAddress()
        if is_exec_addr(program, from_addr):
            f = fm.getFunctionContaining(from_addr)
            if f is None:
                continue
            key = (str(f.getEntryPoint()), f.getName())
            if key in seen_code:
                continue
            seen_code.add(key)
            code_callers.append({"entry": str(f.getEntryPoint()), "name": f.getName()})
        else:
            k = str(from_addr)
            if k in seen_data:
                continue
            seen_data.add(k)
            data_refs.append(str(from_addr))
    return code_callers, data_refs


def sample_neighbor_functions(program, data_addr_str, span_slots=8):
    mem = program.getMemory()
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    base = af.getAddress(data_addr_str.lower())
    if base is None:
        return []
    out = []
    for i in range(-span_slots, span_slots + 1):
        a = base.add(i * 4)
        try:
            v = mem.getInt(a) & 0xFFFFFFFF
        except Exception:
            continue
        va = af.getAddress(hex(v))
        if va is None:
            continue
        f = fm.getFunctionContaining(va)
        if f is None:
            continue
        out.append(
            {
                "slot_delta": i,
                "ptr_value": f"0x{v:08x}",
                "function": f.getName(),
                "entry": str(f.getEntryPoint()),
            }
        )
    return out


def nearest_vtable_candidate(sym_rows, data_addr_int, max_dist=0x200):
    best = None
    for addr_int, name in sym_rows:
        d = abs(addr_int - data_addr_int)
        if d > max_dist:
            continue
        if best is None or d < best[0]:
            best = (d, addr_int, name)
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra-install", required=True, type=Path)
    ap.add_argument("--project-root", required=True, type=Path)
    ap.add_argument("--project-name", default="imperialism-decomp")
    ap.add_argument("--program", default="Imperialism.exe")
    ap.add_argument("--binary-path", type=Path, default=Path("/home/andrzej.gluszak/code/personal/imperialism_knowledge/Imperialism.exe"))
    ap.add_argument("--input", required=True, type=Path, help="aggressive_discovery_*.json")
    ap.add_argument("--out-json", required=True, type=Path)
    ap.add_argument("--out-csv", required=True, type=Path)
    args = ap.parse_args()

    data = json.loads(args.input.read_text())
    residual = [r for r in data.get("virtual_call_functions", []) if str(r.get("function", "")).startswith("Cluster_Vcall_")]
    residual.sort(key=lambda r: int(r.get("vcall_count", 0)), reverse=True)
    log(f"[start] residual_cluster_vcall={len(residual)}")

    pyghidra.start(install_dir=args.ghidra_install)
    rows = []

    with pyghidra.open_program(
        str(args.binary_path),
        project_location=str(args.project_root),
        project_name=args.project_name,
        program_name=args.program,
        analyze=False,
        nested_project_location=False,
    ) as api:
        program = api.currentProgram
        af = program.getAddressFactory().getDefaultAddressSpace()
        st = program.getSymbolTable()

        # Pre-index vtable candidate symbols for nearest lookup.
        vtbl_syms = []
        all_syms = st.getAllSymbols(True)
        for s in all_syms:
            n = s.getName()
            if n.startswith("g_vtblCandidate_") or n.startswith("g_vtblFamily_"):
                try:
                    vtbl_syms.append((int(str(s.getAddress()), 16), n))
                except Exception:
                    pass

        for idx, r in enumerate(residual, 1):
            addr_text = r["address"]
            fn_name = r["function"]
            vcalls = int(r.get("vcall_count", 0))
            offs = ";".join(r.get("offsets", [])[:10])
            addr = af.getAddress(addr_text.lower())
            if addr is None:
                continue

            # Target + alias refs.
            aliases = get_thunk_aliases(program, addr)
            alias_names = [f"{a.getName()}@{a.getEntryPoint()}" for a in aliases]
            all_addrs = [addr] + [a.getEntryPoint() for a in aliases]

            code_callers = []
            data_refs = []
            seen_cc = set()
            seen_dr = set()
            for ta in all_addrs:
                cc, dr = collect_refs(program, ta)
                for c in cc:
                    key = (c["entry"], c["name"])
                    if key in seen_cc:
                        continue
                    seen_cc.add(key)
                    code_callers.append(c)
                for d in dr:
                    if d in seen_dr:
                        continue
                    seen_dr.add(d)
                    data_refs.append(d)

            # For first few data refs, gather neighborhood function pointers and nearest vtable candidate.
            neighbor_samples = []
            nearest_labels = []
            for dref in data_refs[:4]:
                nb = sample_neighbor_functions(program, dref, span_slots=10)
                if nb:
                    neighbor_samples.append({"data_ref": dref, "neighbors": nb})
                try:
                    d_int = int(dref, 16)
                except Exception:
                    continue
                near = nearest_vtable_candidate(vtbl_syms, d_int, max_dist=0x200)
                if near is not None:
                    nearest_labels.append(
                        {
                            "data_ref": dref,
                            "distance": near[0],
                            "candidate_addr": f"0x{near[1]:08x}",
                            "candidate_name": near[2],
                        }
                    )

            rows.append(
                {
                    "address": addr_text,
                    "function": fn_name,
                    "vcall_count": vcalls,
                    "offsets": offs,
                    "aliases": alias_names,
                    "code_callers": code_callers,
                    "data_refs": data_refs,
                    "neighbor_samples": neighbor_samples,
                    "nearest_vtable_labels": nearest_labels,
                }
            )
            if idx % 3 == 0:
                log(f"[progress] {idx}/{len(residual)}")

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps({"rows": rows}, indent=2))
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "address",
                "function",
                "vcall_count",
                "offsets",
                "alias_count",
                "code_caller_count",
                "data_ref_count",
                "alias_examples",
                "caller_examples",
                "nearest_vtable_examples",
            ]
        )
        for r in rows:
            alias_ex = ";".join(r["aliases"][:4])
            caller_ex = ";".join([f"{c['name']}@{c['entry']}" for c in r["code_callers"][:6]])
            near_ex = ";".join([f"{n['candidate_name']}({n['distance']})" for n in r["nearest_vtable_labels"][:4]])
            w.writerow(
                [
                    r["address"],
                    r["function"],
                    r["vcall_count"],
                    r["offsets"],
                    len(r["aliases"]),
                    len(r["code_callers"]),
                    len(r["data_refs"]),
                    alias_ex,
                    caller_ex,
                    near_ex,
                ]
            )

    log(f"[done] wrote {args.out_json} and {args.out_csv} rows={len(rows)}")
    for r in rows:
        log(
            f"{r['address']} {r['function']} vcalls={r['vcall_count']} "
            f"aliases={len(r['aliases'])} callers={len(r['code_callers'])} data_refs={len(r['data_refs'])}"
        )


if __name__ == "__main__":
    main()
