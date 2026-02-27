#!/usr/bin/env python3
"""
Trace bitmap-ID assignments in InitializeTradeScreenBitmapControls and infer
possible derived IDs from pressed-state handlers.

Usage:
  .venv/bin/python new_scripts/trace_trade_bitmap_state_derivations.py \
    --out-csv tmp_decomp/trade_bitmap_call_map.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

TRADE_INIT_ADDR = 0x004601B0
SET_PRESSED_THUNK = 0x004080D0

# ctor address -> (name, class_label, pressed_state_handler?)
CTOR_MAP = {
    0x0040123F: ("ConstructTSliderPictureBaseState", "TSliderPicture", False),
    0x00403BE8: ("ConstructTTradeOrderPictureBaseState", "TTradeOrderPicture", False),
    0x00404331: ("ConstructTradeQuantityArrowPictureEntry", "TSidewaysArrow", True),
    0x004078E2: ("ConstructTradeScreenPictureBaseState", "TradeScreenPicture", False),
    0x00407E69: ("ConstructTTraderAmtBar_Vtbl00666ba0", "TTraderAmtBar", False),
    0x00405628: ("ConstructUiTabCursorPictureEntry", "TPictureButton", False),
    0x00405605: ("ConstructUiResourceEntryTypeB", "TToolBarCluster", False),
    0x00401F28: ("ConstructTMyNumberTextBaseState", "TMyNumberText", False),
    0x004021B2: ("ConstructTDropShadowNumberTextBaseState", "TDropShadowNumberText", False),
}


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument("--out-csv", default="tmp_decomp/trade_bitmap_call_map.csv")
    ap.add_argument(
        "--targets",
        default="2115,2116,2117,2119",
        help="Comma-separated decimal bitmap IDs to explain",
    )
    return ap.parse_args()


def parse_targets(raw: str) -> list[int]:
    out: list[int] = []
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        out.append(int(tok, 10))
    return out


def main() -> int:
    args = parse_args()
    root = Path(args.project_root).resolve()
    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    targets = parse_targets(args.targets)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()

        f = fm.getFunctionAt(af.getAddress(f"0x{TRADE_INIT_ADDR:08x}"))
        if f is None:
            print(f"[error] function missing at 0x{TRADE_INIT_ADDR:08x}")
            return 1

        # Flatten instructions for lookback analysis.
        insns = []
        it = listing.getInstructions(f.getBody(), True)
        while it.hasNext():
            ins = it.next()
            insns.append((ins.getAddress().getOffset() & 0xFFFFFFFF, str(ins)))

        rows: list[dict[str, str]] = []
        literal_ids: set[int] = set()
        derived_ids: set[int] = set()

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

            literal_ids.add(bitmap_id)

            ctor_addr = None
            ctor_name = ""
            class_name = ""
            pressed = False
            for j in range(i - 1, max(-1, i - 161), -1):
                m = re.search(r"CALL 0x([0-9A-Fa-f]{8})", insns[j][1])
                if not m:
                    continue
                t = int(m.group(1), 16)
                if t in CTOR_MAP:
                    ctor_addr = t
                    ctor_name, class_name, pressed = CTOR_MAP[t]
                    break

            if pressed:
                derived_ids.add(bitmap_id - 1)
                derived_ids.add(bitmap_id + 1)

            rows.append(
                {
                    "call_addr": f"0x{addr:08x}",
                    "bitmap_id_dec": str(bitmap_id),
                    "bitmap_id_hex": f"0x{bitmap_id:x}",
                    "ctor_addr": "" if ctor_addr is None else f"0x{ctor_addr:08x}",
                    "ctor_name": ctor_name,
                    "class_name": class_name,
                    "pressed_derivation_possible": "1" if pressed else "0",
                    "derived_minus_1": str(bitmap_id - 1) if pressed else "",
                    "derived_plus_1": str(bitmap_id + 1) if pressed else "",
                }
            )

        with out_csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(
                fh,
                fieldnames=[
                    "call_addr",
                    "bitmap_id_dec",
                    "bitmap_id_hex",
                    "ctor_addr",
                    "ctor_name",
                    "class_name",
                    "pressed_derivation_possible",
                    "derived_minus_1",
                    "derived_plus_1",
                ],
            )
            w.writeheader()
            w.writerows(rows)

        print(f"[saved] {out_csv} rows={len(rows)}")
        print(f"trade_initializer=0x{TRADE_INIT_ADDR:08x} {f.getName()}")
        print("literal_bitmap_ids:", ",".join(str(x) for x in sorted(literal_ids)))
        print("derived_bitmap_ids_from_pressed_classes:", ",".join(str(x) for x in sorted(derived_ids)))

        for t in targets:
            in_literal = t in literal_ids
            in_derived = t in derived_ids
            if in_literal:
                state = "literal"
            elif in_derived:
                state = "derived(+/-1)"
            else:
                state = "absent"
            print(f"target {t}: {state}")

        print(f"pressed_handler_thunk=0x{SET_PRESSED_THUNK:08x}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

