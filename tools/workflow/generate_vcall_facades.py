#!/usr/bin/env python3
"""Generate typed vtable call facades from config/vtable_slots.csv."""

from __future__ import annotations

import argparse
from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path

VALID_CALLCONV = {"fastcall", "thiscall", "cdecl", "stdcall"}
VALID_SLOT_UNIT = {"expr", "index", "byte_offset"}
VALID_EDX_MODE = {"zero", "explicit", "none"}


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--slots-csv",
        default=str(repo_root / "config" / "vtable_slots.csv"),
        help="Pipe-delimited slot registry path.",
    )
    parser.add_argument(
        "--output",
        default=str(repo_root / "include" / "game" / "generated" / "vcall_facades.h"),
        help="Generated facade header output path.",
    )
    parser.add_argument(
        "--owner-file",
        action="append",
        default=[],
        help="Optional owner_file filter. May be passed multiple times.",
    )
    return parser.parse_args()


def parse_arg_types(value: str) -> list[str]:
    raw = value.strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def parse_optional(row: dict[str, str], key: str, default: str) -> str:
    value = row.get(key)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def parse_int(value: str) -> int:
    raw = value.strip().lower()
    if raw.startswith("0x"):
        return int(raw, 16)
    return int(raw, 10)


def normalize_slot_expr(slot_expr: str, slot_unit: str) -> str:
    if slot_unit == "byte_offset":
        return f"({slot_expr}) / 4"
    return slot_expr


def validate_row(
    wrapper_name: str,
    callconv: str,
    slot_unit: str,
    edx_mode: str,
    edx_value: str,
    arity: int,
    return_type: str,
) -> None:
    if callconv not in VALID_CALLCONV:
        raise ValueError(f"{wrapper_name}: invalid callconv '{callconv}'")
    if slot_unit not in VALID_SLOT_UNIT:
        raise ValueError(f"{wrapper_name}: invalid slot_unit '{slot_unit}'")
    if edx_mode not in VALID_EDX_MODE:
        raise ValueError(f"{wrapper_name}: invalid edx_mode '{edx_mode}'")

    if callconv in {"cdecl", "stdcall"} and edx_mode != "none":
        raise ValueError(f"{wrapper_name}: callconv '{callconv}' requires edx_mode 'none'")

    if callconv == "thiscall" and edx_mode == "explicit":
        raise ValueError(f"{wrapper_name}: callconv 'thiscall' does not support edx_mode 'explicit'")

    if edx_mode == "explicit":
        if callconv != "fastcall":
            raise ValueError(f"{wrapper_name}: edx_mode 'explicit' is only supported for callconv 'fastcall'")
        if arity not in {2, 3}:
            raise ValueError(
                f"{wrapper_name}: edx_mode 'explicit' currently supports arity 2 or 3, got {arity}"
            )
        if not edx_value.strip():
            raise ValueError(f"{wrapper_name}: edx_mode 'explicit' requires edx_value")
        parse_int(edx_value)

    if edx_mode == "none" and callconv == "fastcall":
        raise ValueError(f"{wrapper_name}: callconv 'fastcall' requires edx_mode 'zero' or 'explicit'")

    if arity > 4:
        raise ValueError(f"{wrapper_name}: unsupported arity {arity}, max is 4")

    if return_type.strip() == "":
        raise ValueError(f"{wrapper_name}: missing return_type")


def runtime_fn_name(callconv: str, arity: int, is_void: bool, edx_mode: str) -> str:
    suffix = "v" if is_void else ""
    base = f"{callconv}{arity}{suffix}"
    if callconv == "fastcall" and edx_mode == "explicit":
        return f"{base}_with_edx"
    return base


def render_fn_typedef(
    callconv: str,
    return_type: str,
    arg_types: list[str],
    include_edx: bool,
) -> str:
    if callconv in {"fastcall", "thiscall"}:
        parts = ["void*", "int"] if include_edx else ["void*"]
        parts.extend(arg_types)
        return f"{return_type} (__fastcall * Fn)({', '.join(parts)})"
    if callconv == "cdecl":
        parts = ["void*"]
        parts.extend(arg_types)
        return f"{return_type} (__cdecl * Fn)({', '.join(parts)})"
    if callconv == "stdcall":
        parts = ["void*"]
        parts.extend(arg_types)
        return f"{return_type} (__stdcall * Fn)({', '.join(parts)})"
    raise ValueError(f"Unsupported callconv '{callconv}'")


def render_direct_call(
    callconv: str,
    slot_value: str,
    args: list[str],
    edx_mode: str,
    edx_value: str,
) -> tuple[str, str]:
    if callconv in {"fastcall", "thiscall"}:
        include_edx = edx_mode in {"zero", "explicit"}
        fn_typedef = render_fn_typedef(callconv, "void", [], include_edx)
        call_args = ["object"]
        if edx_mode == "explicit":
            call_args.append(str(parse_int(edx_value)))
        elif include_edx:
            call_args.append("0")
        call_args.extend(args)
        return fn_typedef, f"fn({', '.join(call_args)})"

    fn_typedef = render_fn_typedef(callconv, "void", [], False)
    call_args = ["object"]
    call_args.extend(args)
    return fn_typedef, f"fn({', '.join(call_args)})"


def render_wrapper(
    wrapper_name: str,
    return_type: str,
    slot_expr: str,
    arg_types: list[str],
    note: str,
    callconv: str,
    slot_unit: str,
    edx_mode: str,
    edx_value: str,
    status: str,
    class_name: str,
) -> list[str]:
    arity = len(arg_types)
    validate_row(
        wrapper_name=wrapper_name,
        callconv=callconv,
        slot_unit=slot_unit,
        edx_mode=edx_mode,
        edx_value=edx_value,
        arity=arity,
        return_type=return_type,
    )

    params = ["void* object"]
    args = []
    for idx, arg_type in enumerate(arg_types):
        arg_name = f"arg{idx}"
        params.append(f"{arg_type} {arg_name}")
        args.append(arg_name)

    lines: list[str] = []
    comment_parts = [note]
    if class_name:
        comment_parts.append(f"class={class_name}")
    if status:
        comment_parts.append(f"status={status}")
    lines.append(f"// {'; '.join([part for part in comment_parts if part]).rstrip()}".rstrip())
    signature = f"static __inline {return_type} {wrapper_name}({', '.join(params)}) {{"
    lines.append(signature)
    normalized_slot_expr = normalize_slot_expr(slot_expr, slot_unit)
    slot_value = f"static_cast<unsigned int>({normalized_slot_expr})"
    include_edx = callconv in {"fastcall", "thiscall"} and edx_mode in {"zero", "explicit"}
    fn_typedef = render_fn_typedef(
        callconv=callconv,
        return_type=return_type,
        arg_types=arg_types,
        include_edx=include_edx,
    )
    lines.append(f"  typedef {fn_typedef};")
    lines.append(f"  Fn fn = reinterpret_cast<Fn>(vcall_runtime::resolve_slot(object, {slot_value}));")

    _, call_expr = render_direct_call(
        callconv=callconv,
        slot_value=slot_value,
        args=args,
        edx_mode=edx_mode,
        edx_value=edx_value,
    )
    if return_type == "void":
        lines.append(f"  {call_expr};")
        lines.append("}")
        return lines

    lines.append(f"  return {call_expr};")
    lines.append("}")
    return lines


def build_header(rows: list[dict[str, str]]) -> str:
    out: list[str] = []
    out.append("// AUTOGENERATED FILE. DO NOT EDIT.")
    out.append("// Generated by tools/workflow/generate_vcall_facades.py")
    out.append("#pragma once")
    out.append("")
    out.append('#include "game/vcall_runtime.h"')
    out.append("")

    seen_wrappers: set[str] = set()
    for row in rows:
        wrapper_name = (row.get("wrapper_name") or "").strip()
        return_type = (row.get("return_type") or "").strip()
        slot_expr = (row.get("slot_expr") or "").strip()
        notes = (row.get("notes") or "").strip()
        arg_types = parse_arg_types(row.get("arg_types") or "")
        callconv = parse_optional(row, "callconv", "fastcall")
        slot_unit = parse_optional(row, "slot_unit", "expr")
        edx_mode = parse_optional(row, "edx_mode", "zero")
        edx_value = parse_optional(row, "edx_value", "")
        status = parse_optional(row, "status", "provisional")
        class_name = parse_optional(row, "class_name", "")

        if not wrapper_name:
            raise ValueError("Row missing wrapper_name")
        if not slot_expr:
            raise ValueError(f"{wrapper_name}: missing slot_expr")
        if wrapper_name in seen_wrappers:
            raise ValueError(f"Duplicate wrapper_name '{wrapper_name}'")
        seen_wrappers.add(wrapper_name)

        out.extend(
            render_wrapper(
                wrapper_name=wrapper_name,
                return_type=return_type,
                slot_expr=slot_expr,
                arg_types=arg_types,
                note=notes,
                callconv=callconv,
                slot_unit=slot_unit,
                edx_mode=edx_mode,
                edx_value=edx_value,
                status=status,
                class_name=class_name,
            )
        )
        out.append("")

    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    slots_csv = resolve_repo_path(repo_root, args.slots_csv)
    output = resolve_repo_path(repo_root, args.output)

    rows = read_pipe_rows(slots_csv)
    if args.owner_file:
        owner_set = set(args.owner_file)
        rows = [row for row in rows if (row.get("owner_file") or "").strip() in owner_set]

    rows.sort(
        key=lambda row: (
            (row.get("owner_file") or "").strip(),
            (row.get("wrapper_name") or "").strip(),
        )
    )

    rendered = build_header(rows)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(f"Wrote {output} ({len(rows)} wrappers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
