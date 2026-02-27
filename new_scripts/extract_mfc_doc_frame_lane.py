#!/usr/bin/env python3
"""
Extract/normalize MFC document-frame lane in a target address range.

Actions:
  1) Ensure class namespaces exist (CDocument/CDocTemplate/CWinApp/CFrameWnd).
  2) Attach Global functions to those classes by conservative name patterns.
  3) Signature sweep: for attached methods with generic first param and non-thiscall
     calling convention, set calling convention to __thiscall.

Usage:
  .venv/bin/python new_scripts/extract_mfc_doc_frame_lane.py --dry-run
  .venv/bin/python new_scripts/extract_mfc_doc_frame_lane.py --apply
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def in_lane(addr: int) -> bool:
    return 0x00610000 <= addr < 0x0061F000


RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "CFrameWnd",
        re.compile(
            r"^(SetActiveView|OnUpdateFrameTitle|UpdateFrameTitleForDocument|InitialUpdateFrame|"
            r"ShowControlBar|OnInitMenuPopup|OnSetMessageString|OnEnterIdle|DestroyDockBars|"
            r"OnUpdateContextHelp|CanCloseFrame|LoadFrame|OnClose|OnDestroy|OnDropFiles|OnEndSession)$",
            re.IGNORECASE,
        ),
    ),
    (
        "CDocTemplate",
        re.compile(
            r"^(OpenDocumentFile|GetOpenDocumentCount|MatchDocType|CreateNewFrame|CreateOleFrame)$",
            re.IGNORECASE,
        ),
    ),
    (
        "CWinApp",
        re.compile(
            r"^(SaveAllModified|CloseAllDocuments|OnIdle|DoPromptFileName|AddToRecentFileList|"
            r"GetFirstDocTemplatePosition|GetNextDocTemplate|OnFileOpen|WriteProfileInt|WriteProfileStringA|WriteProfileBinary)$",
            re.IGNORECASE,
        ),
    ),
    (
        "CDocument",
        re.compile(
            r"^(GetCDocumentMessageMap|ConstructCDocumentBaseState|DestructCDocumentBaseStateAndMaybeFree|"
            r"DestructCDocumentBaseState|DoFileSave|DoSaveDocumentWithPromptAndReplace|"
            r"SaveModifiedDocumentWithPrompt|ReportDocumentSaveLoadException|OpenFileObjectForDocumentPath|"
            r"OnNewDocument|OnCloseDocument|RemoveView|UpdateAllViews|SendInitialUpdate|SetPathName)$",
            re.IGNORECASE,
        ),
    ),
]


def classify(name: str) -> str | None:
    for cls, rx in RULES:
        if rx.match(name):
            return cls
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()
    do_apply = args.apply and not args.dry_run

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.symbol import SourceType

        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        global_ns = program.getGlobalNamespace()

        class_map = {}
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            ns = it_cls.next()
            class_map[ns.getName()] = ns

        needed = sorted({c for c, _ in RULES})
        to_create = [c for c in needed if c not in class_map]

        attachments = []
        cc_updates = []

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            if not in_lane(addr):
                continue
            if f.getParentNamespace() != global_ns:
                continue
            cls = classify(f.getName())
            if cls is None:
                continue
            attachments.append((f, cls))

        # Preview.
        print(f"[plan] lane=0x00610000..0x0061efff apply={do_apply}")
        print(f"[plan] classes_to_create={len(to_create)}: {', '.join(to_create) if to_create else '<none>'}")
        print(f"[plan] attachments={len(attachments)}")
        for f, cls in attachments[:200]:
            a = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            print(f"  attach 0x{a:08x} {f.getName()} -> {cls}")

        if not do_apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Extract MFC doc/frame lane")
        created_ns = attach_ok = attach_fail = cc_ok = cc_fail = 0
        try:
            # Create missing class namespaces.
            for cls in to_create:
                try:
                    ns = st.createClass(global_ns, cls, SourceType.USER_DEFINED)
                    class_map[cls] = ns
                    created_ns += 1
                except Exception as ex:
                    print(f"[ns-fail] {cls} err={ex}")

            # Attach methods.
            for f, cls in attachments:
                ns = class_map.get(cls)
                if ns is None:
                    attach_fail += 1
                    continue
                try:
                    f.setParentNamespace(ns)
                    attach_ok += 1
                except Exception as ex:
                    attach_fail += 1
                    a = f.getEntryPoint().getOffset() & 0xFFFFFFFF
                    print(f"[attach-fail] 0x{a:08x} {f.getName()} -> {cls} err={ex}")

            # Signature sweep: thiscall for obvious method-shaped signatures.
            for f, _cls in attachments:
                try:
                    params = f.getParameters()
                    if len(params) == 0:
                        continue
                    p0 = params[0]
                    p0t = p0.getDataType().getName().lower()
                    if "void *" not in p0t and "undefined" not in p0t:
                        continue
                    cc = f.getCallingConventionName() or ""
                    if cc == "__thiscall":
                        continue
                    f.setCallingConvention("__thiscall")
                    cc_ok += 1
                except Exception as ex:
                    cc_fail += 1
                    a = f.getEntryPoint().getOffset() & 0xFFFFFFFF
                    print(f"[cc-fail] 0x{a:08x} {f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("extract mfc doc frame lane", None)
        print(
            f"[done] created_ns={created_ns} attach_ok={attach_ok} attach_fail={attach_fail} "
            f"cc_ok={cc_ok} cc_fail={cc_fail}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

