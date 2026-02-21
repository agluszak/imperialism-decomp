#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--out-json", required=True, type=Path)
    ap.add_argument("--out-csv", required=True, type=Path)
    args = ap.parse_args()

    data = json.loads(args.input.read_text())
    rows = data.get("vtable_candidates", [])

    fam_map = {}
    for r in rows:
        key = tuple(r.get("sample_functions", [])[:4])
        fam = fam_map.setdefault(
            key,
            {
                "family_id": None,
                "signature": list(key),
                "count": 0,
                "members": [],
                "max_run_len": 0,
                "min_run_len": 1 << 30,
            },
        )
        fam["count"] += 1
        rl = int(r.get("run_len", 0))
        fam["max_run_len"] = max(fam["max_run_len"], rl)
        fam["min_run_len"] = min(fam["min_run_len"], rl)
        fam["members"].append(
            {
                "address": r.get("address"),
                "run_len": rl,
                "block": r.get("block"),
            }
        )

    fams = list(fam_map.values())
    fams.sort(key=lambda f: f["count"], reverse=True)
    for i, f in enumerate(fams, 1):
        f["family_id"] = f"VF{i:03d}"
        f["members"].sort(key=lambda m: m["run_len"], reverse=True)

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps({"families": fams}, indent=2))

    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "family_id",
                "count",
                "min_run_len",
                "max_run_len",
                "sig0",
                "sig1",
                "sig2",
                "sig3",
                "member_addresses",
            ]
        )
        for f in fams:
            mem = ";".join([m["address"] for m in f["members"][:20]])
            sig = f["signature"] + ["", "", "", ""]
            w.writerow(
                [
                    f["family_id"],
                    f["count"],
                    f["min_run_len"],
                    f["max_run_len"],
                    sig[0],
                    sig[1],
                    sig[2],
                    sig[3],
                    mem,
                ]
            )

    print(f"families={len(fams)}")
    print(f"wrote_json={args.out_json}")
    print(f"wrote_csv={args.out_csv}")
    for f in fams[:10]:
        print(f"{f['family_id']} count={f['count']} run={f['min_run_len']}..{f['max_run_len']}")


if __name__ == "__main__":
    main()
