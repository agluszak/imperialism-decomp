#!/usr/bin/env python3
"""
Create raw diplomacy enums and annotate high-signal constants in diplomacy handlers.

This is intentionally raw/non-semantic:
  - EDiplomacyRelationCodeRaw  (2..6)
  - EDiplomacyActionCodeRaw    (0,1,10,13,60)

Annotations are restricted to a curated function set and to CMP/PUSH sites
to avoid broad noise from generic MOV/ADD constants.
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

REL_FUNCS = {
    "BuildNationActionOptionCardsFromRelationTable",
    "RefreshNationStatusDialogRowsAndSummaryMessage",
    "RenderMapDialogDiplomacyNeighborRelationHints",
}
ACT_FUNCS = {
    "ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode",
    "ValidateDiplomacyProposalTargetAndShowBlockedDetails",
    "RunDiplomacyNegotiationPopupAndAwaitResponse",
    "RunDiplomacyWaitSheetPopupAndAwaitResponse",
    "HandleDiplomacyTurnEventPacketByCode",
}

REL_VALUES = {2, 3, 4, 5, 6}
ACT_VALUES = {0, 1, 10, 13, 60}


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler, EnumDataType
        from ghidra.program.model.listing import CodeUnit

        dtm = program.getDataTypeManager()
        fm = program.getFunctionManager()
        listing = program.getListing()

        tx = program.startTransaction("Create diplomacy raw enums + annotate")
        try:
            # Enums
            rel = EnumDataType(CategoryPath("/Imperialism"), "EDiplomacyRelationCodeRaw", 2)
            for v in sorted(REL_VALUES):
                rel.add(f"DIP_REL_RAW_{v}", v)
            rel = dtm.addDataType(rel, DataTypeConflictHandler.REPLACE_HANDLER)

            act = EnumDataType(CategoryPath("/Imperialism"), "EDiplomacyActionCodeRaw", 2)
            for v in sorted(ACT_VALUES):
                act.add(f"DIP_ACT_RAW_{v}", v)
            act = dtm.addDataType(act, DataTypeConflictHandler.REPLACE_HANDLER)

            print(f"[enum] {rel.getPathName()} values={sorted(REL_VALUES)}")
            print(f"[enum] {act.getPathName()} values={sorted(ACT_VALUES)}")

            # Annotation pass
            ann = 0
            scanned = 0
            fit = fm.getFunctions(True)
            while fit.hasNext():
                fn = fit.next()
                name = fn.getName()
                domain = None
                values = None
                if name in REL_FUNCS:
                    domain = "REL"
                    values = REL_VALUES
                elif name in ACT_FUNCS:
                    domain = "ACT"
                    values = ACT_VALUES
                else:
                    continue
                scanned += 1

                ins_it = listing.getInstructions(fn.getBody(), True)
                while ins_it.hasNext():
                    ins = ins_it.next()
                    mnem = str(ins.getMnemonicString()).upper()
                    if mnem not in ("CMP", "PUSH"):
                        continue

                    hit = None
                    for oi in range(ins.getNumOperands()):
                        sc = ins.getScalar(oi)
                        if sc is None:
                            continue
                        v = int(sc.getUnsignedValue()) & 0xFFFFFFFF
                        if v in values:
                            hit = v
                            break
                    if hit is None:
                        continue

                    if domain == "REL":
                        c = (
                            f"EDiplomacyRelationCodeRaw::DIP_REL_RAW_{hit} "
                            f"(raw relation code {hit})"
                        )
                    else:
                        c = (
                            f"EDiplomacyActionCodeRaw::DIP_ACT_RAW_{hit} "
                            f"(raw action code {hit})"
                        )
                    prev = listing.getComment(CodeUnit.EOL_COMMENT, ins.getAddress())
                    if prev == c:
                        continue
                    listing.setComment(ins.getAddress(), CodeUnit.EOL_COMMENT, c)
                    ann += 1
                    print(f"[annotated] {ins.getAddress()} {name}: {c}")

            print(f"[annotate] scanned={scanned} set={ann}")
        finally:
            program.endTransaction(tx, True)

        program.save("create diplomacy raw enums and annotate constants", None)
        print("[done]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

