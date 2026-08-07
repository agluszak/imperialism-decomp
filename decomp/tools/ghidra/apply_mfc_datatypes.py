#!/usr/bin/env python3
r"""Apply a small VC5/MFC 4.2 core datatype pack to the vendored Ghidra DB.

The layouts here are from the matching Docker toolchain:

    C:\msvc\mfc\include
    C:\msvc\mfc\lib\nafxcw.lib

Sizes and offsets were checked with the VC5 compiler under Wine. This is not a
full MFC import; it is a conservative core pack for the classes that show up
most often in Imperialism decompilation and MFC RTTI recovery.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import pyghidra

from tools.common import ghidra_env


DEFAULT_CLASSES = (
    "CStringData",
    "CString",
    "CRuntimeClass",
    "CObject",
    "CPtrList",
    "CArchive",
    "CDC",
    "CCmdTarget",
    "CWnd",
    "CDataExchange",
    "CView",
    "CFile",
    "COleDataObject",
    "CGdiObject",
    "CFont",
    "CScrollBar",
    "CCommandLineInfo",
    "CDumpContext",
    "CException",
    "CMenu",
    "CWinThread",
)


@dataclass(frozen=True)
class FieldSpec:
    offset: int
    name: str
    type_name: str
    size: int


@dataclass(frozen=True)
class ClassSpec:
    name: str
    size: int
    fields: tuple[FieldSpec, ...]
    dependencies: tuple[str, ...] = ()
    category: str = "/MFC/library"


MFC_MODELS: dict[str, ClassSpec] = {
    "CStringData": ClassSpec(
        name="CStringData",
        size=0x0C,
        fields=(
            FieldSpec(0x00, "nRefs", "long", 4),
            FieldSpec(0x04, "nDataLength", "int", 4),
            FieldSpec(0x08, "nAllocLength", "int", 4),
        ),
    ),
    "CString": ClassSpec(
        name="CString",
        size=0x04,
        dependencies=("CStringData",),
        fields=(FieldSpec(0x00, "m_pchData", "char *", 4),),
    ),
    "CRuntimeClass": ClassSpec(
        name="CRuntimeClass",
        size=0x18,
        fields=(
            FieldSpec(0x00, "m_lpszClassName", "char *", 4),
            FieldSpec(0x04, "m_nObjectSize", "int", 4),
            FieldSpec(0x08, "m_wSchema", "int", 4),
            FieldSpec(0x0C, "m_pfnCreateObject", "void *", 4),
            FieldSpec(0x10, "m_pBaseClass", "CRuntimeClass *", 4),
            FieldSpec(0x14, "m_pNextClass", "CRuntimeClass *", 4),
        ),
    ),
    "CObject": ClassSpec(
        name="CObject",
        size=0x04,
        fields=(FieldSpec(0x00, "vftable", "void *", 4),),
    ),
    "CPtrList": ClassSpec(
        name="CPtrList",
        size=0x1C,
        dependencies=("CObject",),
        fields=(
            FieldSpec(0x00, "cobject", "CObject", 4),
            FieldSpec(0x04, "m_pNodeHead", "void *", 4),
            FieldSpec(0x08, "m_pNodeTail", "void *", 4),
            FieldSpec(0x0C, "m_nCount", "int", 4),
            FieldSpec(0x10, "m_pNodeFree", "void *", 4),
            FieldSpec(0x14, "m_pBlocks", "void *", 4),
            FieldSpec(0x18, "m_nBlockSize", "int", 4),
        ),
    ),
    "CArchive": ClassSpec(
        name="CArchive",
        size=0x44,
        dependencies=("CString",),
        fields=(
            FieldSpec(0x00, "m_pDocument", "void *", 4),
            FieldSpec(0x04, "m_bForceFlat", "int", 4),
            FieldSpec(0x08, "m_bDirectBuffer", "int", 4),
            FieldSpec(0x0C, "m_nObjectSchema", "int", 4),
            FieldSpec(0x10, "m_strFileName", "CString", 4),
            FieldSpec(0x14, "m_nMode", "int", 4),
            FieldSpec(0x18, "m_bUserBuf", "int", 4),
            FieldSpec(0x1C, "m_nBufSize", "int", 4),
            FieldSpec(0x20, "m_pFile", "void *", 4),
            FieldSpec(0x24, "m_lpBufCur", "byte *", 4),
            FieldSpec(0x28, "m_lpBufMax", "byte *", 4),
            FieldSpec(0x2C, "m_lpBufStart", "byte *", 4),
            FieldSpec(0x30, "m_nMapCount", "int", 4),
            FieldSpec(0x34, "m_pLoadArrayOrStoreMap", "void *", 4),
            FieldSpec(0x38, "m_pSchemaMap", "void *", 4),
            FieldSpec(0x3C, "m_nGrowSize", "int", 4),
            FieldSpec(0x40, "m_nHashSize", "int", 4),
        ),
    ),
    "CDC": ClassSpec(
        name="CDC",
        size=0x10,
        dependencies=("CObject",),
        fields=(
            FieldSpec(0x00, "cobject", "CObject", 4),
            FieldSpec(0x04, "m_hDC", "void *", 4),
            FieldSpec(0x08, "m_hAttribDC", "void *", 4),
            FieldSpec(0x0C, "m_bPrinting", "int", 4),
        ),
    ),
    "CCmdTarget": ClassSpec(
        name="CCmdTarget",
        size=0x1C,
        dependencies=("CObject",),
        fields=(
            FieldSpec(0x00, "cobject", "CObject", 4),
            FieldSpec(0x04, "m_dwRef", "long", 4),
            FieldSpec(0x08, "m_pOuterUnknown", "void *", 4),
            FieldSpec(0x0C, "m_xInnerUnknown", "int", 4),
            FieldSpec(0x10, "m_xDispatch", "int", 4),
            FieldSpec(0x14, "m_bResultExpected", "int", 4),
            FieldSpec(0x18, "m_xConnPtContainer", "int", 4),
        ),
    ),
    "CWnd": ClassSpec(
        name="CWnd",
        size=0x3C,
        dependencies=("CCmdTarget",),
        fields=(
            FieldSpec(0x00, "ccmdTarget", "CCmdTarget", 0x1C),
            FieldSpec(0x1C, "m_hWnd", "void *", 4),
            FieldSpec(0x20, "m_hWndOwner", "void *", 4),
            FieldSpec(0x24, "m_nFlags", "int", 4),
            FieldSpec(0x28, "m_pfnSuper", "void *", 4),
            FieldSpec(0x2C, "m_nModalResult", "int", 4),
            FieldSpec(0x30, "m_pDropTarget", "void *", 4),
            FieldSpec(0x34, "m_pCtrlCont", "void *", 4),
            FieldSpec(0x38, "m_pCtrlSite", "void *", 4),
        ),
    ),
    # Layout verified against the vendored MFC 4.2 header
    # (vendor/msvc500/headers/mfc/include/afxwin.h:1224-1245) — a small, fixed,
    # publicly-documented DDX/DDV context struct with only 4 scalar/pointer
    # members, not a game class. Was previously an empty/opaque Ghidra stub
    # (TypeResolver's `opaque_pointee` grade), the single largest weak-pointer
    # bucket in the structural signature audit: ~23 `DoDataExchange(CDataExchange*)`
    # overrides across the MFC dialog-template classes all graded opaque_pointee
    # purely because this ONE type had no real size/fields, even though every
    # signature was already logically/ABI converged (the pointer's own 4 bytes
    # were always correct — only the SEMANTIC type-identity grade was weak).
    "CDataExchange": ClassSpec(
        name="CDataExchange",
        size=0x10,
        dependencies=("CWnd",),
        fields=(
            FieldSpec(0x00, "m_bSaveAndValidate", "int", 4),   # BOOL
            FieldSpec(0x04, "m_pDlgWnd", "CWnd *", 4),
            FieldSpec(0x08, "m_hWndLastControl", "void *", 4),  # HWND
            FieldSpec(0x0C, "m_bEditLastControl", "int", 4),   # BOOL
        ),
    ),
    # afxwin.h:3536-3612 — CView adds exactly one field (m_pDocument) over its
    # CWnd base; every other member in the header is a method/virtual, not
    # storage. m_pDocument is modelled as `void *` (CDocument's own layout is
    # out of scope here — only CView's SIZE needs to stop being opaque).
    "CView": ClassSpec(
        name="CView",
        size=0x40,
        dependencies=("CWnd",),
        fields=(
            FieldSpec(0x00, "cwnd", "CWnd", 0x3C),
            FieldSpec(0x3C, "m_pDocument", "void *", 4),
        ),
    ),
    # The following 8 were driven by weak_pointer_type_inventory.py's
    # canonical_mfc_type_exists bucket (docs/reference/apply-mfc-rtti-ownership.md-
    # adjacent follow-up work) — each layout measured from the vendored MFC 4.2
    # header, not guessed. CPrintInfo and CTypeLibCache remain unmodeled: neither
    # has a real definition anywhere in the vendored header subset (only a
    # forward declaration), so staying opaque is honest, not a defect;
    # CPreviewView is deferred (needs CSize/CScrollView first, for a single
    # occurrence).
    #
    # afx.h:1154-1256 — CFile derives CObject; three scalar/CString fields.
    "CFile": ClassSpec(
        name="CFile",
        size=0x10,
        dependencies=("CObject", "CString"),
        fields=(
            FieldSpec(0x00, "cobject", "CObject", 4),
            FieldSpec(0x04, "m_hFile", "int", 4),            # UINT
            FieldSpec(0x08, "m_bCloseOnDelete", "int", 4),   # BOOL
            FieldSpec(0x0C, "m_strFileName", "CString", 4),
        ),
    ),
    # afxole.h:148-189 — COleDataObject is NOT CObject-derived (no vfptr); a
    # plain 4-field wrapper around IDataObject.
    "COleDataObject": ClassSpec(
        name="COleDataObject",
        size=0x10,
        fields=(
            FieldSpec(0x00, "m_lpDataObject", "void *", 4),   # LPDATAOBJECT
            FieldSpec(0x04, "m_lpEnumerator", "void *", 4),   # LPENUMFORMATETC
            FieldSpec(0x08, "m_bClipboard", "int", 4),        # BOOL
            FieldSpec(0x0C, "m_bAutoRelease", "int", 4),      # BOOL
        ),
    ),
    # afxwin.h:343-377 — CGdiObject derives CObject; one HGDIOBJ handle field.
    # Modeled as a dependency of CFont (below), which adds no fields of its own.
    "CGdiObject": ClassSpec(
        name="CGdiObject",
        size=0x08,
        dependencies=("CObject",),
        fields=(
            FieldSpec(0x00, "cobject", "CObject", 4),
            FieldSpec(0x04, "m_hObject", "void *", 4),  # HGDIOBJ
        ),
    ),
    # afxwin.h:451-479 — CFont adds no fields over CGdiObject.
    "CFont": ClassSpec(
        name="CFont",
        size=0x08,
        dependencies=("CGdiObject",),
        fields=(
            FieldSpec(0x00, "cgdiobject", "CGdiObject", 8),
        ),
    ),
    # afxwin.h:3041-3066 — CScrollBar adds no fields over CWnd.
    "CScrollBar": ClassSpec(
        name="CScrollBar",
        size=0x3C,
        dependencies=("CWnd",),
        fields=(
            FieldSpec(0x00, "cwnd", "CWnd", 0x3C),
        ),
    ),
    # afxwin.h:3921-3956 — CCommandLineInfo derives CObject; 4 scalar fields
    # followed by 4 CString fields (release build; no _DEBUG-only members).
    "CCommandLineInfo": ClassSpec(
        name="CCommandLineInfo",
        size=0x24,
        dependencies=("CObject", "CString"),
        fields=(
            FieldSpec(0x00, "cobject", "CObject", 4),
            FieldSpec(0x04, "m_bShowSplash", "int", 4),      # BOOL
            FieldSpec(0x08, "m_bRunEmbedded", "int", 4),     # BOOL
            FieldSpec(0x0C, "m_bRunAutomated", "int", 4),    # BOOL
            FieldSpec(0x10, "m_nShellCommand", "int", 4),    # enum
            FieldSpec(0x14, "m_strFileName", "CString", 4),
            FieldSpec(0x18, "m_strPrinterName", "CString", 4),
            FieldSpec(0x1C, "m_strDriverName", "CString", 4),
            FieldSpec(0x20, "m_strPortName", "CString", 4),
        ),
    ),
    # afx.h:1834-1875 — CDumpContext is NOT CObject-derived; 2 fields.
    "CDumpContext": ClassSpec(
        name="CDumpContext",
        size=0x08,
        dependencies=("CFile",),
        fields=(
            FieldSpec(0x00, "m_nDepth", "int", 4),
            FieldSpec(0x04, "m_pFile", "CFile *", 4),
        ),
    ),
    # afx.h:823-849 — CException derives CObject; one BOOL field (release
    # build; m_bReadyForDelete is _DEBUG-only).
    "CException": ClassSpec(
        name="CException",
        size=0x08,
        dependencies=("CObject",),
        fields=(
            FieldSpec(0x00, "cobject", "CObject", 4),
            FieldSpec(0x04, "m_bAutoDelete", "int", 4),  # BOOL
        ),
    ),
    # afxwin.h:1077-1097 — CMenu derives CObject; one HMENU handle field.
    "CMenu": ClassSpec(
        name="CMenu",
        size=0x08,
        dependencies=("CObject",),
        fields=(
            FieldSpec(0x00, "cobject", "CObject", 4),
            FieldSpec(0x04, "m_hMenu", "void *", 4),  # HMENU
        ),
    ),
    # afxwin.h:3776-3835 — CWinThread derives CCmdTarget; 5 scalar/pointer
    # fields (release build; m_nDisablePumpCount is _DEBUG-only).
    "CWinThread": ClassSpec(
        name="CWinThread",
        size=0x30,
        dependencies=("CCmdTarget", "CWnd"),
        fields=(
            FieldSpec(0x00, "ccmdTarget", "CCmdTarget", 0x1C),
            FieldSpec(0x1C, "m_pMainWnd", "CWnd *", 4),
            FieldSpec(0x20, "m_pActiveWnd", "CWnd *", 4),
            FieldSpec(0x24, "m_bAutoDelete", "int", 4),  # BOOL
            FieldSpec(0x28, "m_hThread", "void *", 4),   # HANDLE
            FieldSpec(0x2C, "m_nThreadID", "int", 4),    # DWORD
        ),
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply VC5/MFC core datatypes into Ghidra.")
    parser.add_argument("--apply", action="store_true", help="Write changes (default: dry-run).")
    parser.add_argument(
        "--classes",
        default=",".join(DEFAULT_CLASSES),
        help="Comma-separated class list. Known: {}".format(",".join(MFC_MODELS)),
    )
    return parser.parse_args()


def parse_classes(raw: str) -> list[str]:
    classes = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = [name for name in classes if name not in MFC_MODELS]
    if unknown:
        raise ValueError("unknown MFC class model(s): {}".format(", ".join(unknown)))
    return classes


def expand_dependencies(classes: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    def visit(name: str) -> None:
        if name in seen:
            return
        seen.add(name)
        for dep in MFC_MODELS[name].dependencies:
            visit(dep)
        out.append(name)

    for cls in classes:
        visit(cls)
    return out


def primitive_datatype(type_name: str):
    from ghidra.program.model.data import (
        ByteDataType,
        CharDataType,
        IntegerDataType,
        LongDataType,
        VoidDataType,
    )

    return {
        "byte": ByteDataType.dataType,
        "char": CharDataType.dataType,
        "int": IntegerDataType.dataType,
        "long": LongDataType.dataType,
        "void": VoidDataType.dataType,
    }.get(type_name)


def datatype_for(type_name: str, dtm, created):
    from ghidra.program.model.data import ArrayDataType, PointerDataType, VoidDataType

    if type_name == "void *":
        return PointerDataType(VoidDataType.dataType, dtm)
    if type_name.endswith(" *"):
        base_name = type_name.removesuffix(" *")
        base_dt = datatype_for(base_name, dtm, created)
        return PointerDataType(base_dt, dtm)
    if "[" in type_name and type_name.endswith("]"):
        base_name, count_text = type_name[:-1].split("[", 1)
        base_dt = datatype_for(base_name, dtm, created)
        return ArrayDataType(base_dt, int(count_text, 0), base_dt.getLength(), dtm)
    primitive = primitive_datatype(type_name)
    if primitive is not None:
        return primitive
    if type_name in created:
        return created[type_name]
    raise ValueError(f"datatype is not available yet: {type_name}")


def replace_datatype(dtm, datatype):
    from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler

    existing = dtm.getDataType(CategoryPath.ROOT, datatype.getName())
    if existing is not None:
        return dtm.replaceDataType(existing, datatype, True)
    return dtm.addDataType(datatype, DataTypeConflictHandler.REPLACE_HANDLER)


def mirror_to_mfc_category(dtm, root_datatype, category_path: str):
    from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler

    category = CategoryPath(category_path)
    existing = dtm.getDataType(category, root_datatype.getName())
    if existing is not None:
        return dtm.replaceDataType(existing, root_datatype.copy(dtm), True)
    return dtm.addDataType(root_datatype.copy(dtm), DataTypeConflictHandler.REPLACE_HANDLER)


def build_datatypes(program, class_names: list[str]):
    from ghidra.program.model.data import CategoryPath, StructureDataType

    dtm = program.getDataTypeManager()
    created = {
        name: StructureDataType(CategoryPath.ROOT, name, MFC_MODELS[name].size, dtm)
        for name in class_names
    }
    for name in class_names:
        spec = MFC_MODELS[name]
        struct = created[name]
        for field in spec.fields:
            field_dt = datatype_for(field.type_name, dtm, created)
            struct.replaceAtOffset(field.offset, field_dt, field.size, field.name, None)
        root_dt = replace_datatype(dtm, struct)
        created[name] = root_dt
        mirror_to_mfc_category(dtm, root_dt, spec.category)
    return created


def main() -> int:
    args = parse_args()
    selected = expand_dependencies(parse_classes(args.classes))
    print("Selected MFC datatype models:")
    for name in selected:
        spec = MFC_MODELS[name]
        print(f"  {name}: size=0x{spec.size:x} fields={len(spec.fields)}")
    if not args.apply:
        print("Re-run with --apply to write these changes to the Ghidra DB.")
        return 0

    project = ghidra_env.open_project()
    consumer = None
    program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=True)
        txid = program.startTransaction("apply VC5/MFC core datatypes")
        created = build_datatypes(program, selected)
        program.endTransaction(txid, True)
        txid = None
        program.save("apply VC5/MFC core datatypes", pyghidra.task_monitor())
        print(f"Applied {len(created)} MFC datatypes.")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
