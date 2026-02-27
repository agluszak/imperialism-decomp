#!/usr/bin/env python3
"""
Build a gameplay enum specification JSON from enum candidate CSV rows.

Input CSV expected columns (minimum):
  domain, enum_path, immediate_value|immediate_hex, evidence_strength, cluster_key
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import project_category_path, project_datatype_path, split_datatype_path
from imperialism_re.core.enum_candidates import (
    load_candidate_rows,
    parse_domains_filter,
    parse_optional_int_token,
    row_cluster_key,
    row_domain,
    row_enum_path,
    row_evidence_strength,
    row_immediate_value,
)


def _sanitize_token(text: str) -> str:
    t = re.sub(r"[^A-Za-z0-9]+", "_", text.strip().upper())
    t = re.sub(r"_+", "_", t).strip("_")
    if not t:
        return "VALUE"
    if not re.match(r"^[A-Z_]", t):
        t = "V_" + t
    return t


def _domain_to_enum_path(domain: str) -> str:
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", domain) if p]
    camel = "".join(p[:1].upper() + p[1:] for p in parts) or "Domain"
    return project_datatype_path(f"E{camel}")


def _decode_tag_le(value: int) -> str | None:
    try:
        b = int(value).to_bytes(4, byteorder="little", signed=False)
    except Exception:
        return None
    if all(32 <= x < 127 for x in b):
        return b.decode("ascii", errors="ignore")
    return None


def _member_name(domain: str, value: int, taken: set[str]) -> str:
    domain_tok = _sanitize_token(domain)
    tag = _decode_tag_le(value)
    if tag is not None:
        base = f"{domain_tok}_TAG_{_sanitize_token(tag)}"
    else:
        base = f"{domain_tok}_VALUE_{value:08X}"

    name = base
    idx = 2
    while name in taken:
        name = f"{base}_{idx}"
        idx += 1
    taken.add(name)
    return name


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--min-evidence", type=int, default=3)
    ap.add_argument("--cluster-threshold", type=int, default=1)
    ap.add_argument("--domains", default="", help="Optional comma-separated domain filter")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)

    in_csv = Path(args.in_csv)
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    if not in_csv.exists():
        print(f"[error] missing in-csv: {in_csv}")
        return 1

    out_json = Path(args.out_json)
    if not out_json.is_absolute():
        out_json = root / out_json
    out_json.parent.mkdir(parents=True, exist_ok=True)

    domains_filter = parse_domains_filter(args.domains)
    rows = load_candidate_rows(in_csv)

    grouped: dict[tuple[str, str, int], dict[str, object]] = {}
    for row in rows:
        domain = row_domain(row)
        if domains_filter and domain.lower() not in domains_filter:
            continue
        enum_path = row_enum_path(row) or _domain_to_enum_path(domain)
        value = row_immediate_value(row)
        if value is None:
            continue

        key = (domain, enum_path, value)
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "domain": domain,
                "enum_path": enum_path,
                "value": value,
                "max_evidence": 0,
                "clusters": set(),
                "row_count": 0,
            }
            grouped[key] = entry

        ev = row_evidence_strength(row)
        if ev > int(entry["max_evidence"]):
            entry["max_evidence"] = ev
        cluster = row_cluster_key(row)
        if cluster:
            entry["clusters"].add(cluster)
        entry["row_count"] = int(entry["row_count"]) + 1

    enum_values: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for entry in grouped.values():
        max_evidence = int(entry["max_evidence"])
        clusters = entry["clusters"]
        cluster_count = len(clusters) if clusters else 1
        if max_evidence < args.min_evidence:
            continue
        if args.cluster_threshold > 1 and cluster_count < args.cluster_threshold:
            continue
        enum_values[(str(entry["domain"]), str(entry["enum_path"]))].append(entry)

    enums = []
    total_values = 0
    for (domain, enum_path) in sorted(enum_values.keys(), key=lambda x: x[1]):
        values = enum_values[(domain, enum_path)]
        if not values:
            continue
        _, enum_name = split_datatype_path(enum_path)
        taken: set[str] = set()
        members = []
        sorted_values = sorted(values, key=lambda v: (int(v["value"]), -int(v["max_evidence"])))
        seen_values = set()
        for v in sorted_values:
            iv = int(v["value"])
            if iv in seen_values:
                continue
            seen_values.add(iv)
            mname = _member_name(domain, iv, taken)
            members.append([mname, iv])

        if not members:
            continue
        enums.append(
            {
                "category": project_category_path(),
                "name": enum_name,
                "size": 4,
                "values": members,
                "meta": {
                    "domain": domain,
                    "enum_path": enum_path,
                    "min_evidence": args.min_evidence,
                    "cluster_threshold": args.cluster_threshold,
                },
            }
        )
        total_values += len(members)

    spec = {
        "enums": enums,
        "tables": [],
        "meta": {
            "source_csv": str(in_csv),
            "domains_filter": sorted(domains_filter),
            "input_rows": len(rows),
            "accepted_enum_count": len(enums),
            "accepted_value_count": total_values,
            "min_evidence": args.min_evidence,
            "cluster_threshold": args.cluster_threshold,
        },
    }

    out_json.write_text(json.dumps(spec, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"[saved] {out_json} enums={len(enums)} values={total_values}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
