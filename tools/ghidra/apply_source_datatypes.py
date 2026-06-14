#!/usr/bin/env python3
"""Apply source-derived class datatypes to the vendored Ghidra project.

This is the generalized version of the focused TView datatype experiment. It
keeps the importer intentionally conservative: only classes listed in
SOURCE_CLASS_MODELS are eligible, and function signature changes are limited to
explicitly listed methods.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import sys

import jpype
import pyghidra

from tools.common import ghidra_env

DEFAULT_CLASSES = ("CString", "TEventHandler", "TView")


@dataclass(frozen=True)
class FieldSpec:
    offset: int
    name: str
    type_name: str
    size: int
    comment: str | None = None


@dataclass(frozen=True)
class ClassSpec:
    name: str
    size: int
    source_path: str
    fields: tuple[FieldSpec, ...]
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionSpec:
    address: int
    class_name: str
    method_name: str
    return_type: str
    params: tuple[tuple[str, str], ...] = ()
    comment: str | None = None


SOURCE_CLASS_MODELS: dict[str, ClassSpec] = {
    "CString": ClassSpec(
        name="CString",
        size=0x04,
        source_path="include/game/CString.h",
        fields=(FieldSpec(0x00, "data_ptr", "int", 4),),
    ),
    "TEventHandler": ClassSpec(
        name="TEventHandler",
        size=0x10,
        source_path="include/game/TEventHandler.h",
        fields=(
            FieldSpec(0x00, "vftable", "void *", 4),
            FieldSpec(0x04, "field04", "int", 4),
            FieldSpec(0x08, "padding_08_to_0b", "undefined4", 4),
            FieldSpec(0x0C, "field0c", "int", 4),
        ),
    ),
    "TView": ClassSpec(
        name="TView",
        size=0x60,
        source_path="include/game/TView.h",
        dependencies=("CString", "TEventHandler"),
        fields=(
            FieldSpec(0x00, "vftable", "void *", 4),
            FieldSpec(0x04, "field04", "int", 4, "TEventHandler"),
            FieldSpec(0x08, "padding_08_to_0b", "undefined4", 4, "TEventHandler"),
            FieldSpec(0x0C, "field0c", "int", 4, "TEventHandler"),
            FieldSpec(0x10, "field10", "int", 4),
            FieldSpec(0x14, "field14", "int", 4),
            FieldSpec(0x18, "field18", "int", 4),
            FieldSpec(0x1C, "controlTag", "int", 4),
            FieldSpec(0x20, "ownerContext", "TView *", 4),
            FieldSpec(0x24, "ownerOffsetX", "int", 4),
            FieldSpec(0x28, "ownerOffsetY", "int", 4),
            FieldSpec(0x2C, "field2c", "int", 4),
            FieldSpec(0x30, "field30", "int", 4),
            FieldSpec(0x34, "field34", "int", 4),
            FieldSpec(0x38, "field38", "int", 4),
            FieldSpec(0x3C, "field3c", "int", 4),
            FieldSpec(0x40, "padding_40_to_43", "undefined4", 4),
            FieldSpec(0x44, "field44", "int", 4),
            FieldSpec(0x48, "field48", "int", 4),
            FieldSpec(0x4C, "flag4c", "byte", 1),
            FieldSpec(0x4D, "flag4d", "byte", 1),
            FieldSpec(0x4E, "field4e", "short", 2),
            FieldSpec(0x50, "field50", "int", 4),
            FieldSpec(0x54, "field54", "short", 2),
            FieldSpec(0x56, "padding_56_to_57", "short", 2),
            FieldSpec(0x58, "sharedStringRef", "CString", 4),
            FieldSpec(0x5C, "field5c", "int", 4),
        ),
    ),
    "TControl": ClassSpec(
        name="TControl",
        size=0x84,
        source_path="include/game/TControl.h",
        dependencies=("TView",),
        fields=(
            FieldSpec(0x00, "tview", "TView", 0x60),
            FieldSpec(0x60, "hasCommandTagResource", "int", 4),
            FieldSpec(0x64, "commandTagResourceByte", "byte", 1),
            FieldSpec(0x65, "padding_65_to_67", "byte[3]", 3),
            FieldSpec(0x68, "field68", "int", 4),
            FieldSpec(0x6C, "field6C", "int", 4),
            FieldSpec(0x70, "field70", "int", 4),
            FieldSpec(0x74, "field74", "int", 4),
            FieldSpec(0x78, "commandTagDefaultParam0", "int", 4),
            FieldSpec(0x7C, "commandTagDefaultParam1", "int", 4),
            FieldSpec(0x80, "commandTagDefaultParam2", "short", 2),
        ),
    ),
    "TAmtBar": ClassSpec(
        name="TAmtBar",
        size=0x68,
        source_path="include/game/TAmtBar.h",
        dependencies=("TView",),
        fields=(
            FieldSpec(0x00, "tview", "TView", 0x60),
            FieldSpec(0x60, "rangeOrMaxValue", "short", 2),
            FieldSpec(0x62, "stepOrCurrentValue", "short", 2),
            FieldSpec(0x64, "auxValueA", "short", 2),
            FieldSpec(0x66, "auxValueB", "short", 2),
        ),
    ),
}

FUNCTION_MODELS: tuple[FunctionSpec, ...] = (
    FunctionSpec(0x0048A8E0, "TView", "ConstructTViewBaseState", "void"),
    FunctionSpec(0x0048A9D0, "TView", "DestructTViewBaseState", "void"),
    FunctionSpec(
        0x0048BEF0,
        "TView",
        "CopyCityDialogStateFromSource",
        "void",
        (("pSource", "TView *"),),
        "Setting prototype: void CopyCityDialogStateFromSource(TView *this, TView *pSource)",
    ),
    FunctionSpec(0x00605797, "CString", "CString", "void"),
    FunctionSpec(0x00605950, "CString", "CString", "void", (("text_or_resource_id", "char *"),)),
    FunctionSpec(0x006058e2, "CString", "~CString", "void"),
    FunctionSpec(0x006057de, "CString", "AllocateBufferForLength", "void", (("text_length", "int"),)),
    FunctionSpec(0x006058b9, "CString", "EnsureCapacityOrAllocate", "void", (("required_capacity", "int"),)),
    FunctionSpec(0x006059fc, "CString", "CopyBufferAndSetLength", "void", (("new_length", "int"), ("src_text", "char *"))),
    FunctionSpec(0x006057a7, "CString", "StringSharedRef_AssignFromPtr", "CString *", (("src_ref", "CString *"),)),
    FunctionSpec(0x00605a29, "CString", "AssignFromPtr", "CString *", (("src_ref", "CString *"),)),
    FunctionSpec(0x00605a78, "CString", "CopyFromCStr", "CString *", (("src_text", "char *"),)),
    FunctionSpec(0x00605ae0, "CString", "ConcatenateBuffers", "void", (("lhs_len", "int"), ("lhs_text", "char *"), ("rhs_len", "int"), ("rhs_text", "char *"))),
    FunctionSpec(0x0060588b, "CString", "EnsureUniqueSharedStringBuffer", "void"),
    FunctionSpec(0x00605c6f, "CString", "AppendBuffer", "void", (("append_len", "int"), ("append_text", "char *"))),
    FunctionSpec(0x00605cce, "CString", "AssignFromCStr", "undefined4", (("text", "char *"),)),
    FunctionSpec(0x00605d22, "CString", "EnsureCapacityPreserveLength", "int", (("min_capacity", "int"),)),
    FunctionSpec(0x00605d99, "CString", "EnsureCapacityAndSetLength", "int", (("new_length", "int"),)),
    FunctionSpec(0x00605d71, "CString", "SetLengthAndTerminator", "void", (("new_length", "int"),)),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--classes",
        default=",".join(DEFAULT_CLASSES),
        help="Comma-separated source class allowlist. Known: {}".format(
            ",".join(SOURCE_CLASS_MODELS)
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print selected classes/functions without mutating Ghidra.",
    )
    return parser.parse_args()


def parse_class_list(raw: str) -> list[str]:
    classes = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = [name for name in classes if name not in SOURCE_CLASS_MODELS]
    if unknown:
        raise ValueError("unknown class model(s): {}".format(", ".join(unknown)))
    return classes


def class_dependencies(spec: ClassSpec) -> set[str]:
    deps: set[str] = set(spec.dependencies)
    for field in spec.fields:
        base = field.type_name.removesuffix(" *")
        if "[" in base:
            base = base.split("[", 1)[0]
        if base in SOURCE_CLASS_MODELS and base != spec.name:
            deps.add(base)
    return deps


def expand_with_dependencies(classes: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []

    def visit(name: str) -> None:
        if name in seen:
            return
        seen.add(name)
        for dep in sorted(class_dependencies(SOURCE_CLASS_MODELS[name])):
            visit(dep)
        ordered.append(name)

    for cls in classes:
        visit(cls)
    return ordered


def replace_root_datatype(dtm, datatype):
    from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler

    existing = dtm.getDataType(CategoryPath.ROOT, datatype.getName())
    if existing is not None:
        return dtm.replaceDataType(existing, datatype, True)
    return dtm.addDataType(datatype, DataTypeConflictHandler.REPLACE_HANDLER)


def primitive_datatype(type_name: str):
    from ghidra.program.model.data import (
        ByteDataType,
        CharDataType,
        IntegerDataType,
        ShortDataType,
        Undefined4DataType,
        VoidDataType,
    )

    primitives = {
        "byte": ByteDataType.dataType,
        "char": CharDataType.dataType,
        "int": IntegerDataType.dataType,
        "short": ShortDataType.dataType,
        "undefined4": Undefined4DataType.dataType,
        "void": VoidDataType.dataType,
    }
    return primitives.get(type_name)


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


def build_class_datatypes(program, class_names: list[str]) -> dict[str, object]:
    from ghidra.program.model.data import CategoryPath, StructureDataType

    dtm = program.getDataTypeManager()
    created: dict[str, object] = {
        name: StructureDataType(CategoryPath.ROOT, SOURCE_CLASS_MODELS[name].name, SOURCE_CLASS_MODELS[name].size, dtm)
        for name in class_names
    }
    for class_name in class_names:
        spec = SOURCE_CLASS_MODELS[class_name]
        struct = created[class_name]
        for field in spec.fields:
            field_dt = datatype_for(field.type_name, dtm, created)
            struct.replaceAtOffset(field.offset, field_dt, field.size, field.name, field.comment)
        created[class_name] = replace_root_datatype(dtm, struct)
    return created


def return_parameter(type_name: str, program, created):
    from ghidra.program.model.listing import ReturnParameterImpl

    return ReturnParameterImpl(datatype_for(type_name, program.getDataTypeManager(), created), program)


def apply_function_signatures(program, selected_classes: set[str], created) -> int:
    from ghidra.program.model.listing import ParameterImpl
    from ghidra.program.model.symbol import SourceType
    from java.util import ArrayList

    FunctionUpdateType = jpype.JClass("ghidra.program.model.listing.Function$FunctionUpdateType")

    fm = program.getFunctionManager()
    st = program.getSymbolTable()
    af = program.getAddressFactory().getDefaultAddressSpace()
    updated = 0
    for spec in FUNCTION_MODELS:
        if spec.class_name not in selected_classes:
            continue
        fn = fm.getFunctionAt(af.getAddress(spec.address))
        if fn is None:
            raise LookupError(f"no function at 0x{spec.address:08x}")

        ns = st.getNamespace(spec.class_name, program.getGlobalNamespace())
        if ns is None:
            ns = st.createClass(program.getGlobalNamespace(), spec.class_name, SourceType.USER_DEFINED)
        if fn.getParentNamespace() != ns:
            fn.setParentNamespace(ns)
        if fn.getName() != spec.method_name:
            fn.setName(spec.method_name, SourceType.USER_DEFINED)

        params = ArrayList()
        for name, type_name in spec.params:
            params.add(ParameterImpl(name, datatype_for(type_name, program.getDataTypeManager(), created), program))
        fn.updateFunction(
            "__thiscall",
            return_parameter(spec.return_type, program, created),
            params,
            FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            True,
            SourceType.USER_DEFINED,
        )
        if spec.comment is not None and fn.getComment() != spec.comment:
            fn.setComment(spec.comment)
        updated += 1
    return updated


def open_program():
    project = ghidra_env.open_project()
    try:
        consumer, program = ghidra_env.open_program(project, writable=True)
    except FileNotFoundError:
        project.close()
        raise
    return project, consumer, program


def main() -> int:
    args = parse_args()
    requested = parse_class_list(args.classes)
    selected = expand_with_dependencies(requested)
    function_classes = {spec.class_name for spec in FUNCTION_MODELS}

    print("Selected source class models:")
    for class_name in selected:
        spec = SOURCE_CLASS_MODELS[class_name]
        print(f"  {class_name}: size=0x{spec.size:x} fields={len(spec.fields)} source={spec.source_path}")
    print("Function signatures in scope:")
    for spec in FUNCTION_MODELS:
        if spec.class_name in set(selected) & function_classes:
            print(f"  0x{spec.address:08x} {spec.class_name}::{spec.method_name}")
    if args.dry_run:
        return 0

    project, consumer, program = open_program()
    txid = None
    try:
        txid = program.startTransaction("apply source-derived datatype allowlist")
        created = build_class_datatypes(program, selected)
        updated_functions = apply_function_signatures(program, set(selected), created)
        program.endTransaction(txid, True)
        txid = None
        program.save("apply source-derived datatype allowlist", pyghidra.task_monitor())
        print(f"Applied {len(created)} datatypes and {updated_functions} function signatures.")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        program.release(consumer)
        project.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
