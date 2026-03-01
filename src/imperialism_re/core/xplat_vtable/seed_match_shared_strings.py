from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from imperialism_re.core.csvio import load_csv_rows, write_csv_rows


def _meta_index(rows: list[dict[str, str]]) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    for row in rows:
        addr = (row.get("func_addr") or "").strip()
        if not addr:
            continue
        if addr in out:
            continue
        out[addr] = (
            (row.get("func_name") or "").strip(),
            (row.get("class_name") or "").strip(),
        )
    return out


def run(
    *,
    macos_csv: Path,
    windows_csv: Path,
    out_csv: Path,
    max_macos_refs: int,
    max_win_refs: int,
) -> dict[str, int]:
    mac_rows = [
        r for r in load_csv_rows(macos_csv) if (r.get("fingerprint_type") or "") == "string_hash"
    ]
    win_rows = [
        r for r in load_csv_rows(windows_csv) if (r.get("fingerprint_type") or "") == "string_hash"
    ]
    mac_meta = _meta_index(mac_rows)
    win_meta = _meta_index(win_rows)

    mac_by_hash: dict[str, list[dict[str, str]]] = defaultdict(list)
    win_by_hash: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in mac_rows:
        h = (row.get("fingerprint_value") or "").strip()
        if h:
            mac_by_hash[h].append(row)
    for row in win_rows:
        h = (row.get("fingerprint_value") or "").strip()
        if h:
            win_by_hash[h].append(row)

    pair_acc: dict[tuple[str, str], dict[str, object]] = {}
    hash_intersection = sorted(set(mac_by_hash.keys()) & set(win_by_hash.keys()))
    for h in hash_intersection:
        mac_funcs = sorted({(r.get("func_addr") or "").strip() for r in mac_by_hash[h] if r.get("func_addr")})
        win_funcs = sorted({(r.get("func_addr") or "").strip() for r in win_by_hash[h] if r.get("func_addr")})
        if not mac_funcs or not win_funcs:
            continue

        if len(mac_funcs) == 1 and len(win_funcs) == 1:
            pairs = [(mac_funcs[0], win_funcs[0], "function", "high")]
        elif len(mac_funcs) <= max_macos_refs and len(win_funcs) <= max_win_refs:
            pairs = [(ma, wa, "class", "medium") for ma in mac_funcs for wa in win_funcs]
        else:
            continue

        for mac_addr, win_addr, match_type, confidence in pairs:
            key = (mac_addr, win_addr)
            cur = pair_acc.get(key)
            if cur is None:
                cur = {
                    "mac_addr": mac_addr,
                    "win_addr": win_addr,
                    "match_type": match_type,
                    "confidence": confidence,
                    "hashes": set(),
                    "evidence_count": 0,
                }
                pair_acc[key] = cur
            cur["hashes"].add(h)
            cur["evidence_count"] = int(cur["evidence_count"]) + 1
            # Keep the strongest match type/confidence if mixed.
            if match_type == "function":
                cur["match_type"] = "function"
                cur["confidence"] = "high"

    out_rows: list[dict[str, str]] = []
    for (_mac_addr, _win_addr), payload in pair_acc.items():
        mac_addr = str(payload["mac_addr"])
        win_addr = str(payload["win_addr"])
        mac_name, mac_class = mac_meta.get(mac_addr, ("", ""))
        win_name, win_class = win_meta.get(win_addr, ("", ""))
        hashes = sorted(str(x) for x in payload["hashes"])
        out_rows.append(
            {
                "mac_addr": mac_addr,
                "mac_name": mac_name,
                "mac_class": mac_class,
                "win_addr": win_addr,
                "win_name": win_name,
                "win_class": win_class,
                "evidence_count": str(payload["evidence_count"]),
                "match_type": str(payload["match_type"]),
                "confidence": str(payload["confidence"]),
                "evidence_hashes": "|".join(hashes),
            }
        )

    out_rows.sort(
        key=lambda r: (
            -int(r["evidence_count"]),
            r["mac_addr"],
            r["win_addr"],
        )
    )
    write_csv_rows(
        out_csv,
        out_rows,
        [
            "mac_addr",
            "mac_name",
            "mac_class",
            "win_addr",
            "win_name",
            "win_class",
            "evidence_count",
            "match_type",
            "confidence",
            "evidence_hashes",
        ],
    )
    print(f"[seed_match_by_shared_strings] rows={len(out_rows)} -> {out_csv}")
    return {"rows": len(out_rows), "hash_intersection": len(hash_intersection)}

