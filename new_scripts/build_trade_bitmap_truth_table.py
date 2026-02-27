#!/usr/bin/env python3
"""
Build a truth table for trade bitmap IDs and unresolved candidates.

Outputs:
  - tmp_decomp/trade_bitmap_truth_table.csv
  - trade_bitmap_truth_table.md

The table combines:
  - Resource presence from Data/*.gob (wrestool listing)
  - Literal bitmap assignments in InitializeTradeScreenBitmapControls (0x004601b0)
  - Derived +/-1 IDs from pressed-state class paths
  - Global instruction usage of unresolved IDs 2115/2116/2117
"""

from __future__ import annotations

import argparse
import csv
import re
import subprocess
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

TRADE_INIT_ADDR = 0x004601B0
# ctor address -> pressed-state-derivation supported?
CTOR_PRESS_MAP = {
    0x0040123F: False,  # ConstructTSliderPictureBaseState
    0x00403BE8: False,  # ConstructTTradeOrderPictureBaseState
    0x00404331: True,   # ConstructTradeQuantityArrowPictureEntry (TSidewaysArrow)
    0x004078E2: False,  # ConstructTradeScreenPictureBaseState
    0x00407E69: False,  # ConstructTTraderAmtBar_Vtbl00666ba0
    0x00405628: False,  # ConstructUiTabCursorPictureEntry
    0x00405605: False,  # ConstructUiResourceEntryTypeB
    0x00401F28: False,  # ConstructTMyNumberTextBaseState
    0x004021B2: False,  # ConstructTDropShadowNumberTextBaseState
    0x00583B50: True,   # ConstructTSidewaysArrowBaseState
    0x00403512: True,   # thunk_ConstructPictureScreenResourceEntry
    0x005715A0: True,   # ConstructPictureScreenResourceEntry (TUpDownPictureButton)
    0x005717C0: True,   # ConstructUiClickablePictureResourceEntry (TRadioPictureButton)
}

# Known high-confidence semantics from user + verified code paths.
KNOWN_SEMANTICS = {
    2101: "trade_background_pre_oil",
    2102: "trade_background_post_oil",
    2111: "trade_bid_state_a",
    2112: "trade_bid_secondary_state_a",
    2113: "trade_offer_state_a",
    2114: "trade_offer_secondary_state_a",
    2120: "trade_green_control_base",
    2121: "trade_decrease_arrow_base",
    2122: "trade_decrease_arrow_pressed_derived",
    2123: "trade_increase_arrow_base",
    2124: "trade_increase_arrow_pressed_derived",
    2125: "trade_bid_state_b",
    2126: "trade_bid_secondary_state_b",
    2127: "trade_offer_state_b",
    2128: "trade_offer_secondary_state_b",
}


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def wrestool_list(gob_path: Path) -> str:
    p = subprocess.run(
        ["wrestool", "-l", str(gob_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return p.stdout


def extract_bitmap_ids_from_gobs(data_dir: Path, gob_names: list[str]) -> dict[int, list[str]]:
    id_to_gobs: dict[int, list[str]] = defaultdict(list)
    rx = re.compile(r"--type=2\s+--name='(\d+)\.BMP'")
    for gob_name in gob_names:
        gp = data_dir / gob_name
        if not gp.exists():
            continue
        out = wrestool_list(gp)
        for m in rx.finditer(out):
            rid = int(m.group(1), 10)
            id_to_gobs[rid].append(gob_name)
    for rid in id_to_gobs:
        id_to_gobs[rid] = sorted(set(id_to_gobs[rid]))
    return id_to_gobs


def classify_operand_hit(ins_text: str) -> str:
    t = ins_text.upper()
    if "[" in t and "]" in t:
        return "memory_offset_or_disp"
    return "immediate_or_scalar"


def analyze_code(root: Path):
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    literal_trade_ids: set[int] = set()
    derived_ids: set[int] = set()
    unresolved_usage: dict[int, list[tuple[str, str, str]]] = {2115: [], 2116: [], 2117: []}

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()

        trade_fn = fm.getFunctionAt(af.getAddress(f"0x{TRADE_INIT_ADDR:08x}"))
        if trade_fn is not None:
            insns = []
            it = listing.getInstructions(trade_fn.getBody(), True)
            while it.hasNext():
                ins = it.next()
                insns.append((ins.getAddress().getOffset() & 0xFFFFFFFF, str(ins)))

            for i, (addr, text) in enumerate(insns):
                if "CALL dword ptr [" not in text or "+ 0x1c8" not in text:
                    continue
                bitmap_id = None
                for j in range(i - 1, max(-1, i - 6), -1):
                    m = re.search(r"PUSH 0x([0-9A-Fa-f]+)", insns[j][1])
                    if m:
                        bitmap_id = int(m.group(1), 16)
                        break
                if bitmap_id is None:
                    continue
                literal_trade_ids.add(bitmap_id)

                nearest_ctor = None
                for j in range(i - 1, max(-1, i - 220), -1):
                    m = re.search(r"CALL 0x([0-9A-Fa-f]{8})", insns[j][1])
                    if not m:
                        continue
                    tgt = int(m.group(1), 16)
                    if tgt in CTOR_PRESS_MAP:
                        nearest_ctor = tgt
                        break
                if nearest_ctor is not None and CTOR_PRESS_MAP.get(nearest_ctor, False):
                    derived_ids.add(bitmap_id - 1)
                    derived_ids.add(bitmap_id + 1)

        # Global usage scan for unresolved IDs.
        unresolved_hex = {2115: 0x843, 2116: 0x844, 2117: 0x845}
        it_all = listing.getInstructions(True)
        while it_all.hasNext():
            ins = it_all.next()
            ins_text = str(ins)
            addr_s = str(ins.getAddress())
            func = fm.getFunctionContaining(ins.getAddress())
            fn_name = func.getName() if func is not None else "<no_func>"
            for op_idx in range(ins.getNumOperands()):
                for obj in ins.getOpObjects(op_idx):
                    val = None
                    if hasattr(obj, "getUnsignedValue"):
                        try:
                            val = int(obj.getUnsignedValue())
                        except Exception:
                            val = None
                    if val is None and hasattr(obj, "getValue"):
                        try:
                            val = int(obj.getValue())
                        except Exception:
                            val = None
                    if val is None:
                        continue
                    for rid, hx in unresolved_hex.items():
                        if val == hx:
                            unresolved_usage[rid].append(
                                (addr_s, fn_name, classify_operand_hit(ins_text) + f"::{ins_text}")
                            )

    return literal_trade_ids, derived_ids, unresolved_usage


def build_rows(
    id_to_gobs: dict[int, list[str]],
    literal_trade_ids: set[int],
    derived_ids: set[int],
    unresolved_usage: dict[int, list[tuple[str, str, str]]],
):
    ids = sorted(set(range(2101, 2129)) | {2115, 2116, 2117, 2118, 2119})
    rows = []
    for rid in ids:
        gobs = id_to_gobs.get(rid, [])
        present = len(gobs) > 0
        literal = rid in literal_trade_ids
        derived = rid in derived_ids

        if literal:
            classification = "literal_trade_bitmap_id"
        elif derived and not present:
            classification = "derived_runtime_state_id_without_resource"
        elif derived and present:
            classification = "derived_runtime_state_id"
        elif present:
            classification = "resource_present_not_literal_in_trade_init"
        else:
            classification = "absent_from_resources_and_trade_literals"

        if rid in (2115, 2116, 2117):
            hits = unresolved_usage.get(rid, [])
            if not hits:
                classification = "unresolved_candidate_no_code_hits"
            elif rid == 2116:
                classification = "struct_offset_constant_not_bitmap_id"
            else:
                classification = "unresolved_candidate_code_hits"

        notes = []
        sem = KNOWN_SEMANTICS.get(rid)
        if sem:
            notes.append(sem)
        if gobs:
            notes.append("gobs=" + ",".join(gobs))
        if rid in (2115, 2116, 2117):
            hits = unresolved_usage.get(rid, [])
            notes.append(f"global_code_hits={len(hits)}")
            if hits:
                samples = "; ".join(f"{a}:{f}" for a, f, _ in hits[:5])
                notes.append("sample_sites=" + samples)

        rows.append(
            {
                "id": str(rid),
                "hex": f"0x{rid:04x}",
                "resource_present": "1" if present else "0",
                "resource_gobs": ",".join(gobs),
                "literal_in_0x004601b0": "1" if literal else "0",
                "derived_via_pressed_state": "1" if derived else "0",
                "classification": classification,
                "notes": " | ".join(notes),
            }
        )
    return rows


def write_outputs(rows: list[dict[str, str]], csv_path: Path, md_path: Path):
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "id",
                "hex",
                "resource_present",
                "resource_gobs",
                "literal_in_0x004601b0",
                "derived_via_pressed_state",
                "classification",
                "notes",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    lines = []
    lines.append("# Trade Bitmap Truth Table")
    lines.append("")
    lines.append("Grounded sources:")
    lines.append("- GOB resource listings (`pictenu.gob`, `pictpaid.gob`, `pictuniv.gob`)")
    lines.append("- Literal `+0x1c8` picture assignments in `InitializeTradeScreenBitmapControls` (`0x004601b0`)")
    lines.append("- Pressed-state derivation path (`SetPressedStateAdjustPictureBitmapByOne`)")
    lines.append("")
    lines.append("| id | hex | resource_present | resource_gobs | literal_in_0x004601b0 | derived_via_pressed_state | classification | notes |")
    lines.append("|---:|:---:|:---:|:---|:---:|:---:|:---|:---|")
    for r in rows:
        lines.append(
            f"| {r['id']} | `{r['hex']}` | {r['resource_present']} | `{r['resource_gobs']}` | {r['literal_in_0x004601b0']} | {r['derived_via_pressed_state']} | `{r['classification']}` | {r['notes']} |"
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument("--data-dir", default="Data")
    ap.add_argument("--out-csv", default="tmp_decomp/trade_bitmap_truth_table.csv")
    ap.add_argument("--out-md", default="trade_bitmap_truth_table.md")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.project_root).resolve()
    data_dir = (root / args.data_dir).resolve()
    out_csv = (root / args.out_csv).resolve()
    out_md = (root / args.out_md).resolve()

    id_to_gobs = extract_bitmap_ids_from_gobs(
        data_dir, ["pictenu.gob", "pictpaid.gob", "pictuniv.gob"]
    )
    literal_trade_ids, derived_ids, unresolved_usage = analyze_code(root)
    rows = build_rows(id_to_gobs, literal_trade_ids, derived_ids, unresolved_usage)
    write_outputs(rows, out_csv, out_md)

    print(f"[saved] {out_csv}")
    print(f"[saved] {out_md}")
    print("literal_trade_ids:", ",".join(str(x) for x in sorted(literal_trade_ids)))
    print("derived_ids:", ",".join(str(x) for x in sorted(derived_ids)))
    for rid in (2115, 2116, 2117):
        print(f"id={rid} unresolved_hits={len(unresolved_usage.get(rid, []))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
