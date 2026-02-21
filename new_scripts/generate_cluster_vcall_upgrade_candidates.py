#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import pyghidra


DOMAIN_KEYWORDS = {
    "Trade": ["trade", "bid", "offer", "school", "warehouse", "market"],
    "Diplomacy": ["diplomacy", "treaty", "relationship", "embassy", "consulate", "boycott"],
    "City": ["city", "building", "university", "railhead", "engineer", "production", "town"],
    "Military": ["tactical", "battle", "army", "navy", "unit", "garrison", "combat"],
    "Map": ["map", "tile", "terrain", "world", "ocean"],
    "TurnEvent": ["turnevent", "event"],
    "Ui": ["dialog", "window", "view", "control", "screen", "toolbar", "frame"],
}


def score_domain(text_blob: str) -> tuple[str, int]:
    blob = text_blob.lower()
    best = ("Unknown", 0)
    for dom, keys in DOMAIN_KEYWORDS.items():
        s = sum(1 for k in keys if k in blob)
        if s > best[1]:
            best = (dom, s)
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra-install", required=True, type=Path)
    ap.add_argument("--project-root", required=True, type=Path)
    ap.add_argument("--project-name", default="imperialism-decomp")
    ap.add_argument("--program", default="Imperialism.exe")
    ap.add_argument("--binary-path", type=Path, default=Path("/home/andrzej.gluszak/code/personal/imperialism_knowledge/Imperialism.exe"))
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--out-csv", required=True, type=Path)
    ap.add_argument("--out-json", required=True, type=Path)
    ap.add_argument("--limit", type=int, default=120)
    args = ap.parse_args()

    data = json.loads(args.input.read_text())
    vfuncs = [r for r in data.get("virtual_call_functions", []) if str(r.get("function", "")).startswith("Cluster_Vcall_")]
    vfuncs.sort(key=lambda r: int(r.get("vcall_count", 0)), reverse=True)
    if args.limit > 0:
        vfuncs = vfuncs[: args.limit]
    print(f"[start] cluster_vcall funcs={len(vfuncs)}", flush=True)

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
        fm = program.getFunctionManager()
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()
        rm = program.getReferenceManager()

        for idx, r in enumerate(vfuncs, 1):
            addr_text = r["address"]
            fn_name = r["function"]
            vcalls = int(r.get("vcall_count", 0))
            offsets = ",".join(r.get("offsets", [])[:10])
            addr = af.getAddress(addr_text.lower())
            fn = fm.getFunctionAt(addr) if addr else None
            if fn is None:
                continue

            callee_names = []
            callee_seen = set()
            body = fn.getBody()
            ins_it = listing.getInstructions(body, True)
            while ins_it.hasNext():
                ins = ins_it.next()
                if ins.getMnemonicString().upper() != "CALL":
                    continue
                flows = ins.getFlows()
                if flows is None or len(flows) == 0:
                    continue
                to_addr = flows[0]
                cf = fm.getFunctionAt(to_addr)
                if cf is None:
                    cf = fm.getFunctionContaining(to_addr)
                if cf is None:
                    continue
                n = cf.getName()
                if n in callee_seen:
                    continue
                callee_seen.add(n)
                callee_names.append(n)
                if len(callee_names) >= 20:
                    break

            string_hits = []
            str_seen = set()
            cu_it = listing.getCodeUnits(body, True)
            while cu_it.hasNext():
                cu = cu_it.next()
                refs = cu.getReferencesFrom()
                if refs is None:
                    continue
                for ref in refs:
                    ta = ref.getToAddress()
                    if ta is None:
                        continue
                    d = listing.getDefinedDataAt(ta)
                    if d is None:
                        continue
                    v = d.getValue()
                    if v is None:
                        continue
                    s = str(v)
                    if len(s) < 6:
                        continue
                    if s in str_seen:
                        continue
                    str_seen.add(s)
                    string_hits.append(s)
                    if len(string_hits) >= 12:
                        break
                if len(string_hits) >= 12:
                    break

            evidence_blob = " ".join(callee_names + string_hits)
            domain, score = score_domain(evidence_blob)
            suggestion = f"Candidate_{domain}_{addr_text[2:]}"
            rows.append(
                {
                    "address": addr_text,
                    "current_name": fn_name,
                    "vcall_count": vcalls,
                    "offsets": offsets,
                    "domain": domain,
                    "domain_score": score,
                    "suggested_name": suggestion,
                    "top_callees": ";".join(callee_names[:8]),
                    "top_strings": ";".join(string_hits[:6]),
                }
            )
            if idx % 10 == 0:
                print(f"[progress] {idx}/{len(vfuncs)}", flush=True)

    rows.sort(key=lambda x: (x["domain_score"], x["vcall_count"]), reverse=True)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps({"rows": rows}, indent=2))
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "current_name",
                "vcall_count",
                "offsets",
                "domain",
                "domain_score",
                "suggested_name",
                "top_callees",
                "top_strings",
            ],
        )
        w.writeheader()
        w.writerows(rows)
    print(f"[done] wrote {args.out_csv} and {args.out_json} rows={len(rows)}", flush=True)
    for r in rows[:20]:
        print(
            f"{r['address']} {r['current_name']} -> {r['suggested_name']} "
            f"score={r['domain_score']} dom={r['domain']}",
            flush=True,
        )


if __name__ == "__main__":
    main()
