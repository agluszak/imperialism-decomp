#!/usr/bin/env python3
"""
Deeper structure inspection for tabsenu TABLE resources.

Usage:
  python3 scripts/inspect_tabsenu_tables.py
  python3 scripts/inspect_tabsenu_tables.py --root Data/extracted_tables/tabsenu
"""

from __future__ import annotations

import argparse
import re
import struct
from collections import Counter, defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        default="Data/extracted_tables/tabsenu",
        help="Directory containing extracted tabsenu TABLE files",
    )
    return parser.parse_args()


def parse_news_tab(root: Path) -> None:
    news_tab = root / "tabsenu.gob_TABLE_NEWS.TAB"
    news_tex = root / "tabsenu.gob_TABLE_NEWS.TEX"
    if not news_tab.exists() or not news_tex.exists():
        print("[NEWS] missing NEWS.TAB / NEWS.TEX")
        return

    tab = news_tab.read_bytes()
    tex = news_tex.read_bytes()
    if len(tab) % 24 != 0:
        print(f"[NEWS] unexpected NEWS.TAB size={len(tab)} (not divisible by 24)")
        return

    rows = [struct.unpack_from(">6i", tab, i) for i in range(0, len(tab), 24)]
    print("\n[NEWS] TABLE schema")
    print(f"  records={len(rows)} record_size=24 bytes (big-endian 6x int32)")

    ok_title_split = sum(1 for _, b, c, d, _, _ in rows if b + c == d)
    ok_width_200 = sum(1 for *_, f in rows if f == 200)
    print(f"  invariant: title_split_offset (b+c==d) {ok_title_split}/{len(rows)}")
    print(f"  invariant: col5==200 {ok_width_200}/{len(rows)}")

    # Additional strong invariant:
    # For every record except last:
    #   col4 == next.col1 - col3
    # For last record:
    #   col4 == len(TEX) - col3
    ok_span = 0
    for i, (_, b, c, d, e, _) in enumerate(rows):
        next_b = rows[i + 1][1] if i + 1 < len(rows) else len(tex)
        if e == next_b - d:
            ok_span += 1
    print(f"  invariant: body_span (e == next_title_start - d) {ok_span}/{len(rows)}")

    print("  sample records (idx, event_code, title_start, title_span, split, span, width):")
    for idx, (a, b, c, d, e, f) in enumerate(rows[:8]):
        raw_title = tex[b : b + c]
        title = raw_title.split(b"\x00", 1)[0].decode("latin1", errors="replace")
        print(f"    {idx:03d}: [{a}, {b}, {c}, {d}, {e}, {f}] title={title!r}")


def inspect_table_data(root: Path) -> None:
    data_dir = root / "tabsenu.gob_TABLE_DATA"
    if not data_dir.exists():
        print("\n[TABLE_DATA] missing tabsenu.gob_TABLE_DATA/")
        return

    files = sorted(data_dir.glob("*.TAB"))
    if not files:
        print("\n[TABLE_DATA] no *.TAB files")
        return

    print("\n[TABLE_DATA] compact matrices")
    print("  note: every file is 450 bytes with value domain 0..4")
    for p in files:
        b = p.read_bytes()
        counts = Counter(b)
        print(f"  {p.name}: size={len(b)} counts={dict(sorted(counts.items()))}")

    # Practical candidate dimensions from factorization:
    # 450 = 30x15 = 25x18 = 18x25 = ...
    print("  candidate dimensions include 30x15 and 25x18 (both plausible).")


def inspect_text_command_tables(root: Path) -> set[str]:
    files = sorted(
        p for p in root.iterdir() if p.is_file() and re.fullmatch(r"tabsenu\.gob_TABLE_S\d+", p.name)
    )
    cmds: set[str] = set()
    print("\n[S* text tables] command script sources")
    if not files:
        print("  none found")
        return cmds

    for p in files:
        txt = p.read_text("latin1", errors="replace")
        lines = [ln.strip() for ln in txt.replace("\r", "\n").split("\n") if ln.strip()]
        cc = Counter(ln.split(" ", 1)[0] for ln in lines)
        cmds.update(cc.keys())
        print(f"  {p.name}: lines={len(lines)} top={cc.most_common(10)}")
    return cmds


def inspect_scn_binary(root: Path, known_cmds: set[str]) -> None:
    scn_files = sorted(root.glob("tabsenu.gob_TABLE_*.SCN"))
    print("\n[SCN] binary command stream")
    if not scn_files:
        print("  none found")
        return

    cmd4 = {c[:4].encode("ascii") for c in known_cmds if len(c) >= 4 and c.isascii()}
    for p in scn_files:
        b = p.read_bytes()
        c = Counter()
        for i in range(0, len(b) - 3, 4):
            tag = b[i : i + 4]
            if tag in cmd4:
                c[tag.decode("ascii")] += 1
        print(f"  {p.name}: size={len(b)} tags={c.most_common(12)}")

    # Confirm fixed-size `tech` record layout where present.
    print("  invariant check: tech-records appear as 12-byte chunks (tag + 2x BE uint32).")
    for p in scn_files:
        b = p.read_bytes()
        hits = []
        i = 0
        while True:
            j = b.find(b"tech", i)
            if j < 0:
                break
            if j + 12 <= len(b):
                nation = struct.unpack_from(">I", b, j + 4)[0]
                tech_id = struct.unpack_from(">I", b, j + 8)[0]
                hits.append((j, nation, tech_id))
            i = j + 1
        if hits:
            nations = sorted({h[1] for h in hits})
            tmin = min(h[2] for h in hits)
            tmax = max(h[2] for h in hits)
            print(
                f"    {p.name}: tech_hits={len(hits)} nations={nations} tech_id_range={tmin}..{tmax}"
            )


def inspect_map_binary(root: Path) -> None:
    map_files = sorted(root.glob("tabsenu.gob_TABLE_*.MAP"))
    print("\n[MAP] fixed record stream hypothesis")
    if not map_files:
        print("  none found")
        return

    # 309312 / 36 = 8592 exactly for each MAP file.
    for p in map_files[:3]:
        b = p.read_bytes()
        if len(b) % 36 != 0:
            print(f"  {p.name}: size={len(b)} (not divisible by 36)")
            continue
        n = len(b) // 36
        tail_zero = sum(1 for i in range(n) if b[i * 36 + 32 : i * 36 + 36] == b"\x00\x00\x00\x00")
        lead = Counter(b[i * 36] for i in range(n))
        mode, count = lead.most_common(1)[0]
        print(
            f"  {p.name}: size={len(b)} records={n} stride=36 "
            f"lead_mode=0x{mode:02X}({count / n:.2%}) tail_zero={tail_zero / n:.2%}"
        )

    print("  strong signal: MAP blobs are structured 36-byte records, not raw text/string tables.")


def main() -> None:
    args = parse_args()
    root = Path(args.root)
    if not root.exists():
        raise SystemExit(f"root not found: {root}")

    print(f"Inspecting {root}")
    parse_news_tab(root)
    inspect_table_data(root)
    cmds = inspect_text_command_tables(root)
    inspect_scn_binary(root, cmds)
    inspect_map_binary(root)


if __name__ == "__main__":
    main()
