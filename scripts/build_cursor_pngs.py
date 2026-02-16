#!/usr/bin/env python3
"""Build viewable CUR/PNG files from extracted Imperialism EXE cursor blobs.

Input layout expected:
  - Data/extracted_cursors_exe/cursor/*.cur         (raw RT_CURSOR blobs)
  - Data/extracted_cursors_exe/group_cursor/*.cur   (raw RT_GROUP_CURSOR blobs)

Output layout:
  - Data/extracted_cursors_exe/cursor_stdcur/*.cur
  - Data/extracted_cursors_exe/cursor_png/*.png
  - Data/extracted_cursors_exe/group_cursor_stdcur/*.cur
  - Data/extracted_cursors_exe/group_cursor_png/*.png
"""

from __future__ import annotations

import argparse
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CursorImageMeta:
    hotspot_x: int
    hotspot_y: int
    width: int
    height: int
    color_count: int
    bit_count: int
    image_data: bytes


@dataclass(frozen=True)
class GroupCursorEntry:
    width: int
    height: int
    color_count: int
    reserved: int
    planes_or_hotspot_x: int
    bitcount_or_hotspot_y: int
    bytes_in_res: int
    cursor_id: int


def parse_raw_cursor_blob(raw: bytes) -> CursorImageMeta:
    if len(raw) < 44:
        raise ValueError("cursor blob too small")

    hotspot_x, hotspot_y = struct.unpack_from("<HH", raw, 0)
    image = raw[4:]

    # BITMAPINFOHEADER starts at image[0:40]
    # biWidth @ +4 (signed int32), biHeight @ +8 (signed int32, includes AND mask)
    # biBitCount @ +14
    _, bi_width, bi_height, _, bi_bit_count = struct.unpack_from("<IiiHH", image, 0)
    width_px = abs(int(bi_width))
    height_px = abs(int(bi_height)) // 2 if bi_height else 0

    # CUR entry stores 0 for 256 px.
    entry_width = 0 if width_px >= 256 else width_px
    entry_height = 0 if height_px >= 256 else height_px

    if bi_bit_count in (1, 4, 8):
        cc = 1 << bi_bit_count
        color_count = 0 if cc >= 256 else cc
    else:
        color_count = 0

    return CursorImageMeta(
        hotspot_x=hotspot_x,
        hotspot_y=hotspot_y,
        width=entry_width,
        height=entry_height,
        color_count=color_count,
        bit_count=int(bi_bit_count),
        image_data=image,
    )


def build_single_image_cur(meta: CursorImageMeta) -> bytes:
    # ICONDIR header: reserved=0, type=2 (cursor), count=1
    out = bytearray(struct.pack("<HHH", 0, 2, 1))
    # ICONDIRENTRY:
    # width, height, color_count, reserved, hotspot_x, hotspot_y, bytes_in_res, image_offset
    out += struct.pack(
        "<BBBBHHII",
        meta.width & 0xFF,
        meta.height & 0xFF,
        meta.color_count & 0xFF,
        0,
        meta.hotspot_x & 0xFFFF,
        meta.hotspot_y & 0xFFFF,
        len(meta.image_data),
        22,  # 6-byte ICONDIR + 16-byte ICONDIRENTRY
    )
    out += meta.image_data
    return bytes(out)


def parse_group_cursor_blob(blob: bytes) -> list[GroupCursorEntry]:
    if len(blob) < 6:
        raise ValueError("group cursor blob too small")
    reserved, rtype, count = struct.unpack_from("<HHH", blob, 0)
    if reserved != 0 or rtype != 2:
        raise ValueError(f"unexpected group cursor header reserved={reserved} type={rtype}")

    entries: list[GroupCursorEntry] = []
    offset = 6
    for _ in range(count):
        if offset + 14 > len(blob):
            raise ValueError("truncated group cursor entry")
        width, height, color_count, resv, planes, bits, bytes_in_res, cursor_id = struct.unpack_from(
            "<BBBBHHIH", blob, offset
        )
        entries.append(
            GroupCursorEntry(
                width=width,
                height=height,
                color_count=color_count,
                reserved=resv,
                planes_or_hotspot_x=planes,
                bitcount_or_hotspot_y=bits,
                bytes_in_res=bytes_in_res,
                cursor_id=cursor_id,
            )
        )
        offset += 14
    return entries


def png_from_cur(cur_path: Path, png_path: Path) -> None:
    png_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["magick", str(cur_path), str(png_path)], check=True)


def build_cursor_outputs(root: Path) -> tuple[int, int]:
    src_dir = root / "cursor"
    out_cur_dir = root / "cursor_stdcur"
    out_png_dir = root / "cursor_png"
    out_cur_dir.mkdir(parents=True, exist_ok=True)
    out_png_dir.mkdir(parents=True, exist_ok=True)

    cur_count = 0
    png_count = 0
    for raw_path in sorted(src_dir.glob("*.cur"), key=lambda p: int(p.stem)):
        raw = raw_path.read_bytes()
        meta = parse_raw_cursor_blob(raw)
        std_cur = build_single_image_cur(meta)
        out_cur = out_cur_dir / raw_path.name
        out_cur.write_bytes(std_cur)
        cur_count += 1

        out_png = out_png_dir / f"{raw_path.stem}.png"
        png_from_cur(out_cur, out_png)
        png_count += 1
    return cur_count, png_count


def build_group_outputs(root: Path) -> tuple[int, int]:
    src_group_dir = root / "group_cursor"
    src_cursor_dir = root / "cursor"
    out_cur_dir = root / "group_cursor_stdcur"
    out_png_dir = root / "group_cursor_png"
    out_cur_dir.mkdir(parents=True, exist_ok=True)
    out_png_dir.mkdir(parents=True, exist_ok=True)

    cur_count = 0
    png_count = 0
    for group_path in sorted(src_group_dir.glob("*.cur"), key=lambda p: int(p.stem)):
        gid = int(group_path.stem)
        entries = parse_group_cursor_blob(group_path.read_bytes())
        multi = len(entries) > 1
        for idx, entry in enumerate(entries, start=1):
            raw_cursor_path = src_cursor_dir / f"{entry.cursor_id}.cur"
            if not raw_cursor_path.exists():
                raise FileNotFoundError(
                    f"group {gid} references missing raw cursor id {entry.cursor_id}"
                )
            meta = parse_raw_cursor_blob(raw_cursor_path.read_bytes())
            std_cur = build_single_image_cur(meta)
            stem = f"{gid}_{idx}" if multi else f"{gid}"
            out_cur = out_cur_dir / f"{stem}.cur"
            out_cur.write_bytes(std_cur)
            cur_count += 1

            out_png = out_png_dir / f"{stem}.png"
            png_from_cur(out_cur, out_png)
            png_count += 1
    return cur_count, png_count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("Data/extracted_cursors_exe"),
        help="root directory containing cursor/ and group_cursor/ raw dumps",
    )
    args = parser.parse_args()
    root = args.root

    if not (root / "cursor").exists() or not (root / "group_cursor").exists():
        raise SystemExit(f"missing expected folders under {root}")

    c_cur, c_png = build_cursor_outputs(root)
    g_cur, g_png = build_group_outputs(root)
    print(
        f"Built cursor outputs: {c_cur} .cur, {c_png} .png | "
        f"group outputs: {g_cur} .cur, {g_png} .png"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
