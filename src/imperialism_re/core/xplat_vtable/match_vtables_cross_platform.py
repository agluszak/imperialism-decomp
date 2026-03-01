from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from imperialism_re.core.csvio import load_csv_rows, write_csv_rows


def _parse_int(text: str) -> int:
    token = (text or "").strip()
    if not token:
        return 0
    try:
        return int(token, 0)
    except ValueError:
        return int(token, 16)


def _method_key(name: str) -> str:
    v = (name or "").strip()
    if "::" in v:
        v = v.rsplit("::", 1)[1]
    if "(" in v:
        v = v.split("(", 1)[0]
    return v.strip()


def _load_mac_layout(path: Path) -> dict[str, dict[int, str]]:
    rows = load_csv_rows(path)
    out: dict[str, dict[int, str]] = defaultdict(dict)
    for row in rows:
        cls = (row.get("class") or row.get("class_name") or "").strip()
        if not cls:
            continue
        try:
            slot = int((row.get("slot_index") or "").strip())
        except ValueError:
            continue
        name = (row.get("method_name") or "").strip()
        if not name:
            continue
        out[cls][slot] = name
    return dict(out)


def _load_windows_vtables(
    path: Path,
) -> tuple[dict[str, dict[int, tuple[str, str]]], dict[str, str]]:
    rows = load_csv_rows(path)
    out: dict[str, dict[int, tuple[str, str]]] = defaultdict(dict)
    vtable_class: dict[str, str] = {}  # vtable_addr -> class_name (first non-empty wins)
    for row in rows:
        vt = (row.get("vtable_addr") or "").strip()
        if not vt:
            continue
        cn = (row.get("class_name") or "").strip()
        if cn and vt not in vtable_class:
            vtable_class[vt] = cn
        try:
            slot = int((row.get("slot_idx") or "").strip())
        except ValueError:
            continue
        target_addr = (row.get("target_func_addr") or "").strip()
        target_name = (row.get("target_func_name") or "").strip()
        if not target_addr:
            continue
        out[vt][slot] = (target_addr, target_name)
    return dict(out), dict(vtable_class)


def _load_seed_index(path: Path) -> tuple[dict[str, set[str]], dict[str, str]]:
    rows = load_csv_rows(path)
    win_to_mac: dict[str, set[str]] = defaultdict(set)
    win_to_best_match_type: dict[str, str] = {}
    for row in rows:
        confidence = (row.get("confidence") or "").strip().lower()
        match_type = (row.get("match_type") or "").strip().lower()
        if confidence != "high" and match_type != "function":
            continue
        win_addr = (row.get("win_addr") or "").strip()
        mac_name = (row.get("mac_name") or "").strip()
        if not win_addr or not mac_name:
            continue
        win_to_mac[win_addr].add(mac_name)
        win_to_mac[win_addr].add(_method_key(mac_name))
        prev = win_to_best_match_type.get(win_addr)
        if prev != "function":
            win_to_best_match_type[win_addr] = match_type or "function"
    return dict(win_to_mac), win_to_best_match_type


def run(
    *,
    macos_vtable_csv: Path,
    windows_vtable_csv: Path,
    seed_matches_csv: Path,
    out_csv: Path,
    out_slot_map_csv: Path,
    min_score: float,
    max_abi_offset: int,
) -> dict[str, int]:
    mac_layout = _load_mac_layout(macos_vtable_csv)
    win_vtables, vtable_class = _load_windows_vtables(windows_vtable_csv)
    win_to_mac_keys, _win_match_type = _load_seed_index(seed_matches_csv)

    if not mac_layout or not win_vtables:
        write_csv_rows(
            out_csv,
            [],
            [
                "mac_class",
                "win_vtable_addr",
                "total_score",
                "mac_slot",
                "win_slot",
                "mac_method_name",
                "win_func_addr",
                "win_func_name",
                "abi_offset",
            ],
        )
        write_csv_rows(
            out_slot_map_csv,
            [],
            [
                "class_name",
                "slot_index",
                "target_addr",
                "target_name",
                "confidence",
                "winner_writes",
                "total_writes",
                "candidate_count",
                "unique_writers",
                "slot_source",
            ],
        )
        return {"class_matches": 0, "slot_rows": 0}

    win_seed_keys_per_vtable: dict[str, set[str]] = {}
    for vt_addr, slot_map in win_vtables.items():
        keys: set[str] = set()
        for _slot, (fn_addr, _fn_name) in slot_map.items():
            keys.update(win_to_mac_keys.get(fn_addr, set()))
        win_seed_keys_per_vtable[vt_addr] = keys

    detailed_rows: list[dict[str, str]] = []
    slot_rows: list[dict[str, str]] = []
    class_match_count = 0

    for mac_class, mac_slots in sorted(mac_layout.items()):
        if len(mac_slots) < 2:
            continue
        mac_method_keys = {_method_key(name) for name in mac_slots.values()}
        len_mac = (max(mac_slots.keys()) + 1) if mac_slots else 0
        if len_mac <= 0:
            continue

        best: dict[str, object] | None = None
        candidate_count = 0
        for win_vtable_addr, win_slots in win_vtables.items():
            seed_intersection = win_seed_keys_per_vtable.get(win_vtable_addr, set()) & mac_method_keys
            if not seed_intersection:
                continue
            candidate_count += 1

            len_win = (max(win_slots.keys()) + 1) if win_slots else 0
            if len_win <= 0:
                continue
            slot_count_score = 1.0 - (abs(len_mac - len_win) / float(max(len_mac, len_win)))

            local_best: dict[str, object] | None = None
            for abi_off in range(max_abi_offset + 1):
                matched: list[tuple[int, int, str, str, str]] = []
                for mac_slot, mac_method in mac_slots.items():
                    win_slot = mac_slot + abi_off
                    payload = win_slots.get(win_slot)
                    if payload is None:
                        continue
                    win_addr, win_name = payload
                    keys = win_to_mac_keys.get(win_addr, set())
                    mk = _method_key(mac_method)
                    if mac_method in keys or mk in keys:
                        matched.append((mac_slot, win_slot, mac_method, win_addr, win_name))

                matched_slots = len(matched)
                if matched_slots == 0:
                    continue
                seed_score = matched_slots / float(len(mac_slots))
                total_score = 0.6 * seed_score + 0.4 * slot_count_score
                if local_best is None or total_score > float(local_best["score"]):
                    local_best = {
                        "score": total_score,
                        "abi_offset": abi_off,
                        "matched": matched,
                        "win_vtable_addr": win_vtable_addr,
                    }

            if local_best is None:
                continue
            if best is None or float(local_best["score"]) > float(best["score"]):
                best = {
                    **local_best,
                    "candidate_count": candidate_count,
                    "len_mac": len_mac,
                    "len_win": len_win,
                }

        if best is None:
            # Fallback: find Windows vtable attributed to this class by name
            for win_vtable_addr, win_slots in win_vtables.items():
                if (vtable_class.get(win_vtable_addr) or "").lower() != mac_class.lower():
                    continue
                len_win = (max(win_slots.keys()) + 1) if win_slots else 0
                if len_win <= 0:
                    continue
                slot_count_score = 1.0 - abs(len_mac - len_win) / float(max(len_mac, len_win))
                local_best_cn: dict[str, object] | None = None
                for abi_off in range(max_abi_offset + 1):
                    matched: list[tuple[int, int, str, str, str]] = []
                    for mac_slot, mac_method in mac_slots.items():
                        win_slot = mac_slot + abi_off
                        payload = win_slots.get(win_slot)
                        if payload is None:
                            continue
                        win_addr, win_name = payload
                        matched.append((mac_slot, win_slot, mac_method, win_addr, win_name))
                    if not matched:
                        continue
                    slot_overlap = len(matched) / float(len(mac_slots))
                    total_score = 0.4 * slot_overlap + 0.6 * slot_count_score
                    if local_best_cn is None or total_score > float(local_best_cn["score"]):
                        local_best_cn = {
                            "score": total_score,
                            "abi_offset": abi_off,
                            "matched": matched,
                            "win_vtable_addr": win_vtable_addr,
                        }
                if local_best_cn is None:
                    continue
                if best is None or float(local_best_cn["score"]) > float(best["score"]):
                    best = {
                        **local_best_cn,
                        "candidate_count": 1,
                        "len_mac": len_mac,
                        "len_win": len_win,
                        "match_source": "class_name",
                    }

        if best is None:
            continue
        total_score = float(best["score"])
        if total_score < min_score:
            continue

        class_match_count += 1
        win_vtable_addr = str(best["win_vtable_addr"])
        abi_offset = int(best["abi_offset"])
        matched = list(best["matched"])  # type: ignore[arg-type]
        for mac_slot, win_slot, mac_method, win_func_addr, win_func_name in matched:
            detailed_rows.append(
                {
                    "mac_class": mac_class,
                    "win_vtable_addr": win_vtable_addr,
                    "total_score": f"{total_score:.3f}",
                    "mac_slot": str(mac_slot),
                    "win_slot": str(win_slot),
                    "mac_method_name": mac_method,
                    "win_func_addr": win_func_addr,
                    "win_func_name": win_func_name,
                    "abi_offset": str(abi_offset),
                }
            )

        win_slots = win_vtables[win_vtable_addr]
        for mac_slot in sorted(mac_slots.keys()):
            win_slot = mac_slot + abi_offset
            payload = win_slots.get(win_slot)
            if payload is None:
                continue
            target_addr, target_name = payload
            slot_rows.append(
                {
                    "class_name": mac_class,
                    "slot_index": str(mac_slot),
                    "target_addr": target_addr,
                    "target_name": target_name,
                    "confidence": f"{total_score:.3f}",
                    "winner_writes": "1",
                    "total_writes": "1",
                    "candidate_count": str(int(best.get("candidate_count", 1))),
                    "unique_writers": "1",
                    "slot_source": "static_cross_platform_class_name" if best.get("match_source") == "class_name" else "static_cross_platform",
                }
            )
        print(
            f"[match] {mac_class}: win={win_vtable_addr} score={total_score:.3f} "
            f"matched_slots={len(matched)}"
        )

    detailed_rows.sort(key=lambda r: (r["mac_class"], r["win_vtable_addr"], int(r["mac_slot"])))
    slot_rows.sort(key=lambda r: (r["class_name"], int(r["slot_index"])))

    write_csv_rows(
        out_csv,
        detailed_rows,
        [
            "mac_class",
            "win_vtable_addr",
            "total_score",
            "mac_slot",
            "win_slot",
            "mac_method_name",
            "win_func_addr",
            "win_func_name",
            "abi_offset",
        ],
    )
    write_csv_rows(
        out_slot_map_csv,
        slot_rows,
        [
            "class_name",
            "slot_index",
            "target_addr",
            "target_name",
            "confidence",
            "winner_writes",
            "total_writes",
            "candidate_count",
            "unique_writers",
            "slot_source",
        ],
    )
    print(
        f"[match_vtables_cross_platform] class_matches={class_match_count} "
        f"detailed_rows={len(detailed_rows)} slot_rows={len(slot_rows)}"
    )
    return {"class_matches": class_match_count, "detailed_rows": len(detailed_rows), "slot_rows": len(slot_rows)}

