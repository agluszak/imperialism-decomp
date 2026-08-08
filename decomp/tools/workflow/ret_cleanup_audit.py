#!/usr/bin/env python3
"""Find paired functions whose x86 RET cleanup contracts disagree.

Caller and callee can compile successfully from the same wrong C++ prototype.
This audit instead consumes reccmp's bounded structured instruction diff and
compares the original and recompiled ``ret imm16`` values directly.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.common.reccmp_report import run_report
from tools.common.repo import repo_root_from_file


def cleanup(text: str) -> int | None:
    instruction = text.split("\t", 1)[0].strip().lower()
    if instruction == "ret" or instruction == "retn":
        return 0
    for mnemonic in ("ret ", "retn "):
        if instruction.startswith(mnemonic):
            return int(instruction[len(mnemonic) :], 0)
    return None


def ret_contract(entity: dict) -> tuple[set[int], set[int]]:
    original: set[int] = set()
    recompiled: set[int] = set()
    for hunk in entity.get("diff", []):
        for block in hunk[1]:
            for row in block.get("both", []):
                value = cleanup(row[1])
                if value is not None:
                    original.add(value)
                    recompiled.add(value)
            for row in block.get("orig", []):
                value = cleanup(row[1])
                if value is not None:
                    original.add(value)
            for row in block.get("recomp", []):
                value = cleanup(row[1])
                if value is not None:
                    recompiled.add(value)
    return original, recompiled


def main() -> int:
    root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=root / "build-msvc500")
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--address", type=lambda value: int(value, 0))
    args = parser.parse_args()

    addresses = [args.address] if args.address is not None else []
    report = run_report(args.target, args.build_dir, orig_addresses=addresses)
    checked = 0
    conflicts = 0
    for entity in report:
        if entity.get("type") != 1 or not entity.get("recomp"):
            continue
        original, recompiled = ret_contract(entity)
        # An exact/aligned RET is represented under `both`.  If neither side is
        # present, this entity supplied no cleanup evidence and is skipped.
        if not original or not recompiled:
            continue
        checked += 1
        if original != recompiled:
            conflicts += 1
            print(
                f"{entity['address']}|{entity['recomp']}|"
                f"original={sorted(original)}|recompiled={sorted(recompiled)}|"
                f"{entity.get('name', '')}"
            )
    print(f"checked={checked} conflicts={conflicts}")
    return 1 if conflicts else 0


if __name__ == "__main__":
    raise SystemExit(main())
