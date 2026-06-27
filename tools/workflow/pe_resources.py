"""PE .rsrc inventory and extraction for MSVC resource linking."""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

# Win32 resource type ids (winuser.h)
RT_NAMES = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    24: "MANIFEST",
}


@dataclass(frozen=True)
class ResourceEntry:
    type_id: int | str
    name_id: int | str
    lang_id: int
    size: int
    data_offset: int


def _read_u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _read_u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _rva_to_offset(data: bytes, rva: int) -> int:
    e_lfanew = _read_u32(data, 0x3C)
    num_sections = _read_u16(data, e_lfanew + 6)
    opt_size = _read_u16(data, e_lfanew + 20)
    sec_off = e_lfanew + 24 + opt_size
    for i in range(num_sections):
        base = sec_off + i * 40
        vaddr = _read_u32(data, base + 12)
        raw_size = _read_u32(data, base + 16)
        raw_off = _read_u32(data, base + 20)
        if vaddr <= rva < vaddr + raw_size:
            return raw_off + (rva - vaddr)
    raise ValueError(f"RVA 0x{rva:x} not mapped")


def _entry_name(data: bytes, rsrc_base: int, name_or_id: int) -> int | str:
    if name_or_id & 0x80000000:
        str_off = rsrc_base + (name_or_id & 0x7FFFFFFF)
        length = _read_u16(data, str_off)
        return data[str_off + 2 : str_off + 2 + length * 2].decode("utf-16-le")
    return name_or_id


def _parse_dir(
    data: bytes,
    rsrc_base: int,
    dir_off: int,
    type_id: int | str | None = None,
    name_id: int | str | None = None,
) -> list[ResourceEntry]:
    entries: list[ResourceEntry] = []
    num_named = _read_u16(data, dir_off + 12)
    num_id = _read_u16(data, dir_off + 14)
    entry_off = dir_off + 16
    for _ in range(num_named + num_id):
        name_or_id = _read_u32(data, entry_off)
        offset = _read_u32(data, entry_off + 4)
        entry_off += 8
        if offset & 0x80000000:
            child_off = rsrc_base + (offset & 0x7FFFFFFF)
            if type_id is None:
                entries.extend(
                    _parse_dir(
                        data,
                        rsrc_base,
                        child_off,
                        _entry_name(data, rsrc_base, name_or_id),
                        None,
                    )
                )
            elif name_id is None:
                entries.extend(
                    _parse_dir(
                        data,
                        rsrc_base,
                        child_off,
                        type_id,
                        _entry_name(data, rsrc_base, name_or_id),
                    )
                )
            else:
                raise ValueError("unexpected resource subdirectory under language")
        elif type_id is None or name_id is None:
            raise ValueError("unexpected leaf resource directory entry")
        else:
            lang_id = _entry_name(data, rsrc_base, name_or_id)
            if not isinstance(lang_id, int):
                lang_id = 0
            data_entry_off = rsrc_base + offset
            rva = _read_u32(data, data_entry_off)
            size = _read_u32(data, data_entry_off + 4)
            file_off = _rva_to_offset(data, rva)
            entries.append(
                ResourceEntry(type_id, name_id, lang_id, size, file_off)
            )
    return entries


def load_pe_resources(path: Path) -> tuple[bytes, list[ResourceEntry]]:
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError(f"{path}: not a PE file")
    e_lfanew = _read_u32(data, 0x3C)
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ValueError(f"{path}: missing PE signature")
    num_sections = _read_u16(data, e_lfanew + 6)
    opt_size = _read_u16(data, e_lfanew + 20)
    opt_off = e_lfanew + 24
    magic = _read_u16(data, opt_off)
    if magic == 0x10B:
        rsrc_rva = _read_u32(data, opt_off + 112)
    elif magic == 0x20B:
        rsrc_rva = _read_u32(data, opt_off + 136)
    else:
        raise ValueError(f"{path}: unknown optional header magic 0x{magic:x}")
    if rsrc_rva == 0:
        return data, []
    sec_off = e_lfanew + 24 + opt_size
    rsrc_base = None
    for i in range(num_sections):
        base = sec_off + i * 40
        name = data[base : base + 8].split(b"\0")[0]
        if name == b".rsrc":
            vaddr = _read_u32(data, base + 12)
            raw_off = _read_u32(data, base + 20)
            rsrc_base = raw_off + (rsrc_rva - vaddr)
            break
    if rsrc_base is None:
        return data, []
    root_off = rsrc_base
    return data, _parse_dir(data, rsrc_base, root_off)


def type_name(type_id: int | str) -> str:
    if isinstance(type_id, int):
        return RT_NAMES.get(type_id, f"TYPE{type_id}")
    return str(type_id)


def name_label(name_id: int | str) -> str:
    if isinstance(name_id, int):
        return str(name_id)
    return str(name_id)


def format_entry(entry: ResourceEntry) -> str:
    return (
        f"{type_name(entry.type_id):16} id={name_label(entry.name_id):>6} "
        f"lang={entry.lang_id:4} size=0x{entry.size:x}"
    )


def inventory(path: Path, filter_ids: set[int] | None = None) -> list[ResourceEntry]:
    _, entries = load_pe_resources(path)
    if filter_ids is None:
        return entries
    return [
        e
        for e in entries
        if isinstance(e.name_id, int) and e.name_id in filter_ids
    ]


def extract_to_res_inputs(
    pe_path: Path,
    out_dir: Path,
    resource_ids: set[int],
) -> Path:
    """Extract selected resource blobs and write an MSVC .rc stub referencing them."""
    data, entries = load_pe_resources(pe_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_dir = out_dir / "bin"
    bin_dir.mkdir(exist_ok=True)
    rc_lines = [
        "// Auto-generated from retail PE - do not hand-edit blob paths.",
        "",
    ]
    # Types rc.exe accepts as raw PE resource blobs (not file formats like BMP).
    LINKABLE_TYPES = {4, 5, 9, 14, 16, 24}  # MENU, DIALOG, ACCEL, GROUP_ICON, VERSION, MANIFEST
    seen: set[tuple[int | str, int | str]] = set()
    for entry in sorted(
        entries,
        key=lambda e: (
            isinstance(e.type_id, str),
            e.type_id,
            isinstance(e.name_id, str),
            e.name_id,
            e.lang_id,
        ),
    ):
        if not isinstance(entry.name_id, int) or entry.name_id not in resource_ids:
            continue
        key = (entry.type_id, entry.name_id)
        if key in seen:
            continue
        if entry.lang_id not in (0, 1033, 0x409):
            continue
        seen.add(key)
        if not isinstance(entry.type_id, int):
            continue
        if entry.type_id not in LINKABLE_TYPES:
            continue
        blob = data[entry.data_offset : entry.data_offset + entry.size]
        tname = type_name(entry.type_id)
        blob_name = f"{tname.lower()}_{entry.name_id}.bin"
        blob_path = bin_dir / blob_name
        blob_path.write_bytes(blob)
        rel = f"bin/{blob_name}"
        rc_lines.append(f"{entry.name_id} {tname} DISCARDABLE \"{rel}\"")
    rc_path = out_dir / "imperialism_game.rc"
    rc_path.write_text("\n".join(rc_lines) + "\n", encoding="ascii")
    return rc_path


def has_rsrc_section(path: Path) -> bool:
    data = path.read_bytes()
    e_lfanew = _read_u32(data, 0x3C)
    num_sections = _read_u16(data, e_lfanew + 6)
    opt_size = _read_u16(data, e_lfanew + 20)
    sec_off = e_lfanew + 24 + opt_size
    for i in range(num_sections):
        base = sec_off + i * 40
        name = data[base : base + 8].split(b"\0")[0]
        if name == b".rsrc":
            return True
    return False


def check_menu_exists(path: Path, menu_id: int) -> bool:
    _, entries = load_pe_resources(path)
    return any(
        e.type_id == 4 and e.name_id == menu_id for e in entries
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    inv = sub.add_parser("inventory", help="List PE resources")
    inv.add_argument("pe")
    inv.add_argument("--ids", type=int, nargs="*", help="Filter by numeric resource id")

    ext = sub.add_parser("extract-rc", help="Extract resource blobs + write .rc for rc.exe")
    ext.add_argument("pe")
    ext.add_argument("out_dir")
    ext.add_argument("--ids", type=int, nargs="+", required=True)

    chk = sub.add_parser("check", help="Assert .rsrc present and MENU id exists")
    chk.add_argument("pe")
    chk.add_argument("--menu-id", type=int, default=128)

    args = parser.parse_args(argv)
    pe = Path(args.pe)
    if args.cmd == "inventory":
        ids = set(args.ids) if args.ids else None
        for entry in inventory(pe, ids):
            print(format_entry(entry))
        return 0
    if args.cmd == "extract-rc":
        rc = extract_to_res_inputs(pe, Path(args.out_dir), set(args.ids))
        print(rc)
        return 0
    if args.cmd == "check":
        if not has_rsrc_section(pe):
            print(f"FAIL: {pe} has no .rsrc section", file=sys.stderr)
            return 1
        if not check_menu_exists(pe, args.menu_id):
            print(f"FAIL: {pe} has no MENU id {args.menu_id}", file=sys.stderr)
            return 1
        print(f"OK: {pe} has .rsrc and MENU {args.menu_id}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
