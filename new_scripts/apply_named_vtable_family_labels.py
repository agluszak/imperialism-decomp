#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import pyghidra


def log(msg: str):
    print(msg, flush=True)


def infer_family_name(sig: list[str], family_id: str) -> str:
    s0 = sig[0] if len(sig) > 0 else ""
    s1 = sig[1] if len(sig) > 1 else ""
    s2 = sig[2] if len(sig) > 2 else ""
    s3 = sig[3] if len(sig) > 3 else ""
    blob = " ".join([s0, s1, s2, s3]).lower()

    if "dispatchuicommandtohandler" in blob and "forwardcitydialogparamtochild" in blob:
        return "CityDialogDispatchCore"
    if "handleturneventvtableslot08conditionaldispatch" in blob and "handlecitydialognoopslot14" in blob:
        return "TurnEventCityDialogCore"
    if "copypayloadbuffer" in blob and "getcitydialogflagbyte4" in blob:
        return "CityDialogPayloadStateCore"
    if "cloneengineerdialogstate" in blob:
        return "EngineerDialogStateCloneCore"
    if "clonecitydialogextendedstate" in blob:
        return "CityDialogExtendedStateCloneCore"
    if "assertcityproductionglobalstateinitialized" in blob:
        return "CityProductionDialogCore"
    if "getturnviewmanagerclassnamepointer" in blob:
        return "TurnViewManagerCore"
    if "numericentrymethod" in blob:
        return "NumericEntryDialogCore"
    if "getbuildingexpansionviewclassname" in blob:
        return "BuildingExpansionViewCore"
    if "getarmoryviewclassname" in blob:
        return "ArmoryViewCore"
    if "getengineerdialogclassname" in blob:
        return "EngineerDialogCore"
    if "canhandlecitydialogactionfalse" in blob and "getcitydialogvaluedword10" in blob:
        return "CityDialogValueChildAccessCore"
    return f"Family_{family_id}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra-install", required=True, type=Path)
    ap.add_argument("--project-root", required=True, type=Path)
    ap.add_argument("--project-name", default="imperialism-decomp")
    ap.add_argument("--program", default="Imperialism.exe")
    ap.add_argument("--binary-path", type=Path, default=Path("/home/andrzej.gluszak/code/personal/imperialism_knowledge/Imperialism.exe"))
    ap.add_argument("--input", required=True, type=Path, help="vtable_families_*.json")
    ap.add_argument("--max-families", type=int, default=12)
    ap.add_argument("--slot-count", type=int, default=6)
    ap.add_argument("--out-csv", required=True, type=Path)
    args = ap.parse_args()

    fams = json.loads(args.input.read_text()).get("families", [])
    fams = fams[: args.max_families]
    log(f"[start] families={len(fams)} slots_per_family={args.slot_count}")

    pyghidra.start(install_dir=args.ghidra_install)
    with pyghidra.open_program(
        str(args.binary_path),
        project_location=str(args.project_root),
        project_name=args.project_name,
        program_name=args.program,
        analyze=False,
        nested_project_location=False,
    ) as api:
        p = api.currentProgram
        st = p.getSymbolTable()
        af = p.getAddressFactory().getDefaultAddressSpace()
        from ghidra.program.model.symbol import SourceType

        tx = p.startTransaction("Apply named vtable family labels")
        created = 0
        skipped = 0
        rows = []
        try:
            for i, fam in enumerate(fams, 1):
                fid = fam.get("family_id", f"VF{i:03d}")
                sig = fam.get("signature", [])
                members = fam.get("members", [])
                if not members:
                    continue
                root = members[0].get("address")
                root_addr = af.getAddress(str(root).lower())
                if root_addr is None:
                    continue

                base_name = infer_family_name(sig, fid)
                root_label = f"g_vtblFamily_{base_name}_Root"
                slot_labels = [f"g_vtblFamily_{base_name}_Slot{n:02d}" for n in range(args.slot_count)]

                # root label
                exists = any(s.getName() == root_label for s in st.getSymbols(root_addr))
                if not exists:
                    try:
                        st.createLabel(root_addr, root_label, SourceType.USER_DEFINED).setPrimary()
                        created += 1
                    except Exception:
                        skipped += 1
                else:
                    skipped += 1

                # slot labels
                for idx, sl in enumerate(slot_labels):
                    sa = root_addr.add(idx * 4)
                    ex = any(s.getName() == sl for s in st.getSymbols(sa))
                    if ex:
                        skipped += 1
                        continue
                    try:
                        st.createLabel(sa, sl, SourceType.USER_DEFINED)
                        created += 1
                    except Exception:
                        skipped += 1

                rows.append(
                    {
                        "family_id": fid,
                        "family_name": base_name,
                        "count": fam.get("count", 0),
                        "root_address": str(root),
                        "root_label": root_label,
                        "sig0": sig[0] if len(sig) > 0 else "",
                        "sig1": sig[1] if len(sig) > 1 else "",
                        "sig2": sig[2] if len(sig) > 2 else "",
                        "sig3": sig[3] if len(sig) > 3 else "",
                    }
                )
                log(f"[family] {fid} -> {base_name} root={root}")
        finally:
            p.endTransaction(tx, True)

    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "family_id",
                "family_name",
                "count",
                "root_address",
                "root_label",
                "sig0",
                "sig1",
                "sig2",
                "sig3",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    log(f"[done] created={created} skipped={skipped}")
    log(f"[done] wrote {args.out_csv}")


if __name__ == "__main__":
    main()
