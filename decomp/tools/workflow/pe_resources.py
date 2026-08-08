"""PE .rsrc inventory and extraction for MSVC resource linking."""

from __future__ import annotations

import argparse
import re
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


@dataclass(frozen=True)
class GroupCursorImage:
    width: int
    doubled_height: int
    planes: int
    bit_count: int
    resource_size: int
    resource_id: int


@dataclass(frozen=True)
class GroupIconImage:
    width: int
    height: int
    color_count: int
    reserved: int
    planes: int
    bit_count: int
    resource_size: int
    resource_id: int


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


def parse_group_cursor(blob: bytes) -> list[GroupCursorImage]:
    """Parse one RT_GROUP_CURSOR blob.

    Unlike an on-disk .cur directory, Windows stores width/height/planes/bit-count
    words in each group entry. The height is the DIB height and therefore includes
    both the XOR and AND masks.
    """
    if len(blob) < 6:
        raise ValueError("truncated GROUP_CURSOR header")
    reserved, resource_type, count = struct.unpack_from("<HHH", blob, 0)
    if reserved != 0 or resource_type != 2:
        raise ValueError("invalid GROUP_CURSOR header")
    expected_size = 6 + count * 14
    if len(blob) != expected_size:
        raise ValueError(
            f"GROUP_CURSOR size is {len(blob)}, expected {expected_size}"
        )
    images: list[GroupCursorImage] = []
    for index in range(count):
        values = struct.unpack_from("<HHHHIH", blob, 6 + index * 14)
        images.append(GroupCursorImage(*values))
    return images


def build_cursor_file(
    group_blob: bytes,
    cursor_blobs: dict[int, bytes],
) -> bytes:
    """Reconstruct an ordinary .cur file from GROUP_CURSOR + CURSOR resources."""
    group_images = parse_group_cursor(group_blob)
    directory_size = 6 + len(group_images) * 16
    directory = bytearray(struct.pack("<HHH", 0, 2, len(group_images)))
    image_payloads: list[bytes] = []
    image_offset = directory_size
    for group_image in group_images:
        resource_blob = cursor_blobs.get(group_image.resource_id)
        if resource_blob is None:
            raise ValueError(
                f"GROUP_CURSOR references missing CURSOR id {group_image.resource_id}"
            )
        if len(resource_blob) < 4:
            raise ValueError(
                f"CURSOR id {group_image.resource_id} is too small for its hotspot"
            )
        hotspot_x, hotspot_y = struct.unpack_from("<HH", resource_blob, 0)
        image = resource_blob[4:]
        width = 0 if group_image.width >= 256 else group_image.width
        height = group_image.doubled_height // 2
        height_byte = 0 if height >= 256 else height
        color_count = 0
        if 0 < group_image.bit_count < 8:
            color_count = 1 << group_image.bit_count
            if color_count >= 256:
                color_count = 0
        directory.extend(
            struct.pack(
                "<BBBBHHII",
                width,
                height_byte,
                color_count,
                0,
                hotspot_x,
                hotspot_y,
                len(image),
                image_offset,
            )
        )
        image_payloads.append(image)
        image_offset += len(image)
    return bytes(directory) + b"".join(image_payloads)


def parse_group_icon(blob: bytes) -> list[GroupIconImage]:
    """Parse one RT_GROUP_ICON directory."""
    if len(blob) < 6:
        raise ValueError("truncated GROUP_ICON header")
    reserved, resource_type, count = struct.unpack_from("<HHH", blob, 0)
    if reserved != 0 or resource_type != 1:
        raise ValueError("invalid GROUP_ICON header")
    expected_size = 6 + count * 14
    if len(blob) != expected_size:
        raise ValueError(f"GROUP_ICON size is {len(blob)}, expected {expected_size}")
    images: list[GroupIconImage] = []
    for index in range(count):
        values = struct.unpack_from("<BBBBHHIH", blob, 6 + index * 14)
        images.append(GroupIconImage(*values))
    return images


def build_icon_file(group_blob: bytes, icon_blobs: dict[int, bytes]) -> bytes:
    """Reconstruct an ordinary .ico file from GROUP_ICON + ICON resources."""
    group_images = parse_group_icon(group_blob)
    directory_size = 6 + len(group_images) * 16
    directory = bytearray(struct.pack("<HHH", 0, 1, len(group_images)))
    image_payloads: list[bytes] = []
    image_offset = directory_size
    for group_image in group_images:
        image = icon_blobs.get(group_image.resource_id)
        if image is None:
            raise ValueError(
                f"GROUP_ICON references missing ICON id {group_image.resource_id}"
            )
        directory.extend(
            struct.pack(
                "<BBBBHHII",
                group_image.width,
                group_image.height,
                group_image.color_count,
                group_image.reserved,
                group_image.planes,
                group_image.bit_count,
                len(image),
                image_offset,
            )
        )
        image_payloads.append(image)
        image_offset += len(image)
    return bytes(directory) + b"".join(image_payloads)


def build_bitmap_file(resource_dib: bytes) -> bytes:
    """Wrap an RT_BITMAP DIB payload in an ordinary BMP file header."""
    if len(resource_dib) < 12:
        raise ValueError("truncated bitmap resource header")
    header_size = _read_u32(resource_dib, 0)
    if header_size == 12:
        bit_count = _read_u16(resource_dib, 10)
        palette_entry_size = 3
        color_count = (1 << bit_count) if bit_count <= 8 else 0
        extra_mask_size = 0
    elif header_size >= 40 and len(resource_dib) >= header_size:
        bit_count = _read_u16(resource_dib, 14)
        compression = _read_u32(resource_dib, 16)
        color_count = _read_u32(resource_dib, 32)
        if color_count == 0 and bit_count <= 8:
            color_count = 1 << bit_count
        palette_entry_size = 4
        # BITMAPINFOHEADER stores BI_BITFIELDS masks immediately after its
        # 40-byte header. Later V4/V5 headers include the masks themselves.
        extra_mask_size = 12 if header_size == 40 and compression == 3 else 0
    else:
        raise ValueError(f"unsupported bitmap resource header size {header_size}")

    pixel_offset = (
        14 + header_size + extra_mask_size + color_count * palette_entry_size
    )
    file_size = 14 + len(resource_dib)
    file_header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, pixel_offset)
    return file_header + resource_dib


def retail_bitmap_file(pe_path: Path, resource_id: int) -> bytes:
    data, entries = load_pe_resources(pe_path)
    matches = [
        entry
        for entry in entries
        if entry.type_id == 2
        and entry.name_id == resource_id
        and entry.lang_id in (0, 1033, 0x409)
    ]
    if not matches:
        raise ValueError(f"retail PE has no BITMAP id {resource_id}")
    entry = sorted(matches, key=lambda item: item.lang_id)[0]
    dib = data[entry.data_offset : entry.data_offset + entry.size]
    return build_bitmap_file(dib)


def sync_retail_bitmap_file(
    pe_path: Path, resource_id: int, output_path: Path, write: bool
) -> bool:
    expected = retail_bitmap_file(pe_path, resource_id)
    matches = output_path.is_file() and output_path.read_bytes() == expected
    if not matches and write:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(expected)
    return matches


def _retail_resource_blob(
    data: bytes,
    entries: list[ResourceEntry],
    resource_type: int,
    resource_id: int,
    language: int = 1033,
) -> bytes:
    matches = [
        entry
        for entry in entries
        if entry.type_id == resource_type
        and entry.name_id == resource_id
        and entry.lang_id == language
    ]
    if not matches:
        raise ValueError(
            f"retail PE has no {type_name(resource_type)} id {resource_id} lang {language}"
        )
    entry = matches[0]
    return data[entry.data_offset : entry.data_offset + entry.size]


def retail_executable_chrome_files(pe_path: Path) -> dict[str, bytes]:
    """Return direct self-PE resources referenced by recovered production source."""
    data, entries = load_pe_resources(pe_path)
    group_icon = _retail_resource_blob(data, entries, 14, 31234)
    icon_images = {
        entry.name_id: data[entry.data_offset : entry.data_offset + entry.size]
        for entry in entries
        if entry.type_id == 3
        and isinstance(entry.name_id, int)
        and entry.lang_id == 1033
    }
    return {
        "app_7a02.ico": build_icon_file(group_icon, icon_images),
        "version_1.bin": _retail_resource_blob(data, entries, 16, 1),
    }


def sync_retail_executable_chrome_files(
    pe_path: Path, out_dir: Path, write: bool
) -> list[str]:
    expected = retail_executable_chrome_files(pe_path)
    mismatches: list[str] = []
    for filename, content in expected.items():
        path = out_dir / filename
        if not path.is_file() or path.read_bytes() != content:
            mismatches.append(filename)
            if write:
                out_dir.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
    return mismatches


def _pe_group_icon_file(pe_path: Path, group_id: int) -> bytes:
    data, entries = load_pe_resources(pe_path)
    group_blob = _retail_resource_blob(data, entries, 14, group_id)
    icon_images = {
        entry.name_id: data[entry.data_offset : entry.data_offset + entry.size]
        for entry in entries
        if entry.type_id == 3
        and isinstance(entry.name_id, int)
        and entry.lang_id == 1033
    }
    return build_icon_file(group_blob, icon_images)


def direct_resource_parity_mismatches(
    retail_pe: Path, rebuilt_pe: Path
) -> list[str]:
    retail_data, retail_entries = load_pe_resources(retail_pe)
    rebuilt_data, rebuilt_entries = load_pe_resources(rebuilt_pe)
    mismatches: list[str] = []
    for resource_type, resource_id in ((2, 281), (16, 1)):
        retail_blob = _retail_resource_blob(
            retail_data, retail_entries, resource_type, resource_id
        )
        rebuilt_blob = _retail_resource_blob(
            rebuilt_data, rebuilt_entries, resource_type, resource_id
        )
        if rebuilt_blob != retail_blob:
            mismatches.append(f"{type_name(resource_type)} {resource_id}")
    if _pe_group_icon_file(rebuilt_pe, 31234) != _pe_group_icon_file(retail_pe, 31234):
        mismatches.append("GROUP_ICON 31234")
    return mismatches


def build_turn_event_cursor_rc(filenames: list[str]) -> bytes:
    rc_lines = [
        "// Generated from the retail PE by tools.workflow.pe_resources.",
        "// Run `just cursor-resources --write`; do not hand-edit.",
        "",
    ]
    for filename in sorted(
        filenames, key=lambda item: int(re.search(r"\d+", item).group())
    ):
        name = filename[:-4]
        # VC5 rc.exe preserves quotes around a named resource as part of its PE name.
        # These identifiers must decode to ~C1000, not the literal string "~C1000".
        rc_lines.append(f'{name} CURSOR DISCARDABLE "cursors/{filename}"')
    return ("\n".join(rc_lines) + "\n").encode("ascii")


def retail_turn_event_cursor_files(
    pe_path: Path,
    first_resource_id: int = 1000,
    last_resource_id: int = 1053,
) -> dict[str, bytes]:
    data, entries = load_pe_resources(pe_path)
    cursor_blobs: dict[tuple[int, int], bytes] = {}
    groups: dict[tuple[str, int], bytes] = {}
    for entry in entries:
        blob = data[entry.data_offset : entry.data_offset + entry.size]
        if entry.type_id == 1 and isinstance(entry.name_id, int):
            cursor_blobs[(entry.name_id, entry.lang_id)] = blob
        elif entry.type_id == 12 and isinstance(entry.name_id, str):
            groups[(entry.name_id, entry.lang_id)] = blob

    files: dict[str, bytes] = {}
    for cursor_resource_id in range(first_resource_id, last_resource_id + 1):
        name = f"~C{cursor_resource_id}"
        matching_groups = [
            (language, blob)
            for (group_name, language), blob in groups.items()
            if group_name == name
        ]
        if not matching_groups:
            raise ValueError(f"retail PE has no GROUP_CURSOR named {name}")
        language, group_blob = sorted(matching_groups)[0]
        language_cursors = {
            resource_id: blob
            for (resource_id, cursor_language), blob in cursor_blobs.items()
            if cursor_language == language
        }
        files[f"{name}.cur"] = build_cursor_file(group_blob, language_cursors)

    files["cursors.rc"] = build_turn_event_cursor_rc(list(files))
    return files


def sync_retail_turn_event_cursor_files(
    pe_path: Path,
    out_dir: Path,
    write: bool,
) -> list[str]:
    expected = retail_turn_event_cursor_files(pe_path)
    mismatches: list[str] = []
    for filename, content in expected.items():
        path = out_dir / filename
        if not path.is_file() or path.read_bytes() != content:
            mismatches.append(filename)
            if write:
                out_dir.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
    unexpected = sorted(
        path.name
        for path in out_dir.glob("~C*.cur")
        if path.name not in expected
    ) if out_dir.is_dir() else []
    mismatches.extend(unexpected)
    if write:
        for filename in unexpected:
            (out_dir / filename).unlink()
    return mismatches


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


def check_bitmap_exists(path: Path, bitmap_id: int) -> bool:
    _, entries = load_pe_resources(path)
    return any(e.type_id == 2 and e.name_id == bitmap_id for e in entries)


def parse_required_resource(value: str) -> tuple[int, int, int]:
    parts = value.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("resource must be TYPE:ID:LANG")
    try:
        return int(parts[0], 0), int(parts[1], 0), int(parts[2], 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("resource fields must be integers") from exc


def missing_required_resources(
    path: Path, required: list[tuple[int, int, int]]
) -> list[tuple[int, int, int]]:
    _, entries = load_pe_resources(path)
    available = {
        (entry.type_id, entry.name_id, entry.lang_id)
        for entry in entries
        if isinstance(entry.type_id, int) and isinstance(entry.name_id, int)
    }
    return [item for item in required if item not in available]


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
    chk.add_argument("--bitmap-id", type=int)
    chk.add_argument(
        "--require",
        type=parse_required_resource,
        action="append",
        default=[],
        metavar="TYPE:ID:LANG",
    )

    cursors = sub.add_parser(
        "turn-event-cursors",
        help="Check or regenerate the retail ~C1000..~C1053 .cur resources",
    )
    cursors.add_argument("pe")
    cursors.add_argument("out_dir")
    cursor_mode = cursors.add_mutually_exclusive_group(required=True)
    cursor_mode.add_argument("--check", action="store_true")
    cursor_mode.add_argument("--write", action="store_true")

    bitmap = sub.add_parser(
        "bitmap", help="Check or regenerate one retail RT_BITMAP as a BMP file"
    )
    bitmap.add_argument("pe")
    bitmap.add_argument("output")
    bitmap.add_argument("--id", type=int, required=True)
    bitmap_mode = bitmap.add_mutually_exclusive_group(required=True)
    bitmap_mode.add_argument("--check", action="store_true")
    bitmap_mode.add_argument("--write", action="store_true")

    chrome = sub.add_parser(
        "executable-chrome",
        help="Check or regenerate direct retail self-PE icon and version resources",
    )
    chrome.add_argument("pe")
    chrome.add_argument("out_dir")
    chrome_mode = chrome.add_mutually_exclusive_group(required=True)
    chrome_mode.add_argument("--check", action="store_true")
    chrome_mode.add_argument("--write", action="store_true")

    parity = sub.add_parser(
        "direct-resource-parity",
        help="Compare rebuilt direct self-PE resources against retail payloads",
    )
    parity.add_argument("retail_pe")
    parity.add_argument("rebuilt_pe")

    args = parser.parse_args(argv)
    pe = Path(args.pe) if hasattr(args, "pe") else Path(args.retail_pe)
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
        if args.bitmap_id is not None and not check_bitmap_exists(pe, args.bitmap_id):
            print(
                f"FAIL: {pe} has no BITMAP id {args.bitmap_id}", file=sys.stderr
            )
            return 1
        missing = missing_required_resources(pe, args.require)
        if missing:
            for resource_type, resource_id, language in missing:
                print(
                    f"FAIL: {pe} has no {type_name(resource_type)} id {resource_id} "
                    f"lang {language}",
                    file=sys.stderr,
                )
            return 1
        checked = [f"MENU {args.menu_id}"]
        if args.bitmap_id is not None:
            checked.append(f"BITMAP {args.bitmap_id}")
        print(f"OK: {pe} has .rsrc and " + ", ".join(checked))
        return 0
    if args.cmd == "turn-event-cursors":
        mismatches = sync_retail_turn_event_cursor_files(
            pe, Path(args.out_dir), write=args.write
        )
        if args.write:
            print(
                f"Wrote {54} turn-event cursor files and cursors.rc to {args.out_dir}"
            )
            return 0
        if mismatches:
            print(
                "Turn-event cursor resources are stale or missing: "
                + ", ".join(mismatches),
                file=sys.stderr,
            )
            return 1
        print(f"Turn-event cursor resources match {pe}")
        return 0
    if args.cmd == "bitmap":
        matches = sync_retail_bitmap_file(
            pe, args.id, Path(args.output), write=args.write
        )
        if args.write:
            print(f"Wrote retail BITMAP {args.id} to {args.output}")
            return 0
        if not matches:
            print(
                f"Retail BITMAP {args.id} is stale or missing: {args.output}",
                file=sys.stderr,
            )
            return 1
        print(f"Retail BITMAP {args.id} matches {args.output}")
        return 0
    if args.cmd == "executable-chrome":
        mismatches = sync_retail_executable_chrome_files(
            pe, Path(args.out_dir), write=args.write
        )
        if args.write:
            print(f"Wrote retail executable chrome resources to {args.out_dir}")
            return 0
        if mismatches:
            print(
                "Retail executable chrome resources are stale or missing: "
                + ", ".join(mismatches),
                file=sys.stderr,
            )
            return 1
        print(f"Retail executable chrome resources match {pe}")
        return 0
    if args.cmd == "direct-resource-parity":
        mismatches = direct_resource_parity_mismatches(
            Path(args.retail_pe), Path(args.rebuilt_pe)
        )
        if mismatches:
            print(
                "Direct executable resources differ from retail: "
                + ", ".join(mismatches),
                file=sys.stderr,
            )
            return 1
        print("Direct executable resources match retail")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
