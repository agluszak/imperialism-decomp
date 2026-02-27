#!/usr/bin/env python3
"""
Create a symlink-based library subset directory from a list file.

Input list format:
  one relative path per line (relative to --toolchain-root), e.g.:
    lib/LIBC.LIB
    mfc/lib/MFC42.LIB

Usage:
  .venv/bin/python new_scripts/prepare_fid_lib_subset.py \
    --toolchain-root msvc500-master \
    --list-file tmp_decomp/msvc500_fid_phase1_libs.txt \
    --out-dir fid/msvc500_phase1_subset
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--toolchain-root", required=True)
    ap.add_argument("--list-file", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--copy", action="store_true", help="copy files instead of symlink")
    args = ap.parse_args()

    toolchain_root = Path(args.toolchain_root).resolve()
    list_file = Path(args.list_file).resolve()
    out_dir = Path(args.out_dir).resolve()

    if not toolchain_root.exists():
        raise SystemExit(f"missing toolchain root: {toolchain_root}")
    if not list_file.exists():
        raise SystemExit(f"missing list file: {list_file}")

    rel_paths = [
        line.strip()
        for line in list_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not rel_paths:
        raise SystemExit("list file is empty")

    out_dir.mkdir(parents=True, exist_ok=True)

    created = 0
    skipped = 0
    missing = 0
    collisions = 0

    for rel in rel_paths:
        src = (toolchain_root / rel).resolve()
        if not src.exists():
            print(f"[missing] {rel}")
            missing += 1
            continue

        # Keep unique basenames inside subset dir.
        dst = out_dir / src.name
        if dst.exists() or dst.is_symlink():
            if dst.resolve() == src:
                skipped += 1
                continue
            collisions += 1
            stem = src.stem
            suffix = src.suffix
            i = 1
            while True:
                candidate = out_dir / f"{stem}__{i}{suffix}"
                if not candidate.exists() and not candidate.is_symlink():
                    dst = candidate
                    break
                i += 1

        if args.copy:
            dst.write_bytes(src.read_bytes())
        else:
            dst.symlink_to(src)
        created += 1

    print(f"[done] out={out_dir}")
    print(
        f"[counts] requested={len(rel_paths)} created={created} skipped={skipped} "
        f"missing={missing} collisions={collisions}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
