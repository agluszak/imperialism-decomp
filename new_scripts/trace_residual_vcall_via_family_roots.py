#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import pyghidra


def log(msg: str):
    print(msg, flush=True)


def collect_residual_functions(fm):
    out = []
    it = fm.getFunctions(True)
    while it.hasNext():
        f = it.next()
        n = f.getName()
        if n.startswith("Cluster_Vcall_"):
            out.append(f)
    return out


def build_name_index(fm):
    idx = {}
    it = fm.getFunctions(True)
    while it.hasNext():
        f = it.next()
        idx.setdefault(f.getName(), []).append(f)
    return idx


def collect_family_roots(st):
    roots = []
    it = st.getAllSymbols(True)
    while it.hasNext():
        s = it.next()
        n = s.getName()
        if n.startswith("g_vtblFamily_") and n.endswith("_Root"):
            roots.append(s)
    roots.sort(key=lambda s: str(s.getAddress()))
    return roots


def scan_root_table(program, root_addr, max_slots=80):
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    rows = []
    for i in range(max_slots):
        a = root_addr.add(i * 4)
        try:
            v = mem.getInt(a) & 0xFFFFFFFF
        except Exception:
            break
        ta = af.getAddress(hex(v))
        if ta is None:
            continue
        b = mem.getBlock(ta)
        if b is None or not b.isExecute():
            continue
        f = fm.getFunctionContaining(ta)
        if f is None:
            continue
        rows.append((i, str(a), v, f.getName(), str(f.getEntryPoint())))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra-install", required=True, type=Path)
    ap.add_argument("--project-root", required=True, type=Path)
    ap.add_argument("--project-name", default="imperialism-decomp")
    ap.add_argument("--program", default="Imperialism.exe")
    ap.add_argument("--binary-path", type=Path, default=Path("/home/andrzej.gluszak/code/personal/imperialism_knowledge/Imperialism.exe"))
    ap.add_argument("--out-json", required=True, type=Path)
    ap.add_argument("--out-csv", required=True, type=Path)
    ap.add_argument("--max-slots", type=int, default=96)
    args = ap.parse_args()

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
        p = api.currentProgram
        fm = p.getFunctionManager()
        st = p.getSymbolTable()
        rm = p.getReferenceManager()

        residual = collect_residual_functions(fm)
        residual_by_name = {f.getName(): f for f in residual}
        name_index = build_name_index(fm)
        roots = collect_family_roots(st)
        log(f"[start] residual={len(residual)} roots={len(roots)}")

        # Pre-scan tables.
        root_entries = []
        for i, root in enumerate(roots, 1):
            fam_label = root.getName()
            fam_name = fam_label[len("g_vtblFamily_") : -len("_Root")]
            ent = scan_root_table(p, root.getAddress(), max_slots=args.max_slots)
            root_entries.append((fam_name, str(root.getAddress()), ent))
            if i % 5 == 0:
                log(f"[progress] scanned roots {i}/{len(roots)}")

        # For each residual, map direct and alias hits in family tables.
        for rf in residual:
            rname = rf.getName()
            aliases = name_index.get(rname, [])
            alias_entries = {(str(a.getEntryPoint()), a.getName()) for a in aliases}
            addr_set = {str(a.getEntryPoint()) for a in aliases}

            # add tiny thunk aliases that jump to any alias entry
            # (cheap scan over all functions)
            it = fm.getFunctions(True)
            while it.hasNext():
                f = it.next()
                body_size = int(f.getBody().getNumAddresses())
                if body_size > 8:
                    continue
                ep = f.getEntryPoint()
                ins = p.getListing().getInstructionAt(ep)
                if ins is None:
                    continue
                if ins.getMnemonicString().upper() not in ("JMP", "CALL"):
                    continue
                flows = ins.getFlows()
                if flows is None or len(flows) != 1:
                    continue
                dst = str(flows[0])
                if dst in addr_set:
                    alias_entries.add((str(ep), f.getName()))
                    addr_set.add(str(ep))

            family_hits = []
            for fam_name, root_addr, ents in root_entries:
                for slot, slot_addr, ptr_val, fn_name, fn_entry in ents:
                    if fn_entry in addr_set:
                        family_hits.append(
                            {
                                "family": fam_name,
                                "root": root_addr,
                                "slot": slot,
                                "slot_addr": slot_addr,
                                "target_fn": fn_name,
                                "target_entry": fn_entry,
                            }
                        )

            # callers for aliases
            callers = []
            seen_callers = set()
            for ae, _ in alias_entries:
                refs = rm.getReferencesTo(p.getAddressFactory().getDefaultAddressSpace().getAddress("0x" + ae))
                for ref in refs:
                    from_addr = ref.getFromAddress()
                    cf = fm.getFunctionContaining(from_addr)
                    if cf is None:
                        continue
                    k = (str(cf.getEntryPoint()), cf.getName())
                    if k in seen_callers:
                        continue
                    seen_callers.add(k)
                    callers.append({"entry": k[0], "name": k[1]})

            rows.append(
                {
                    "name": rname,
                    "primary_entry": str(rf.getEntryPoint()),
                    "alias_entries": sorted([{"entry": e, "name": n} for e, n in alias_entries], key=lambda x: x["entry"]),
                    "family_hits": family_hits,
                    "callers": callers,
                }
            )

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps({"rows": rows}, indent=2))
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "name",
                "primary_entry",
                "alias_count",
                "family_hit_count",
                "families",
                "callers_count",
                "alias_examples",
                "family_examples",
            ]
        )
        for r in rows:
            fams = sorted({h["family"] for h in r["family_hits"]})
            alias_ex = ";".join([f"{a['name']}@{a['entry']}" for a in r["alias_entries"][:4]])
            fam_ex = ";".join([f"{h['family']}[s{h['slot']}]->{h['target_entry']}" for h in r["family_hits"][:6]])
            w.writerow(
                [
                    r["name"],
                    r["primary_entry"],
                    len(r["alias_entries"]),
                    len(r["family_hits"]),
                    ";".join(fams),
                    len(r["callers"]),
                    alias_ex,
                    fam_ex,
                ]
            )

    log(f"[done] wrote {args.out_json} and {args.out_csv} rows={len(rows)}")
    for r in rows:
        fams = sorted({h["family"] for h in r["family_hits"]})
        log(
            f"{r['name']} primary={r['primary_entry']} aliases={len(r['alias_entries'])} "
            f"family_hits={len(r['family_hits'])} families={','.join(fams) if fams else '-'} callers={len(r['callers'])}"
        )


if __name__ == "__main__":
    main()
