#!/usr/bin/env python3
"""Rewrite reviewed game-method return types by owned function address.

This is deliberately a narrow codemod, not a type-inference tool.  The caller
supplies the proven old and new return types plus one or more function
addresses.  For each address, the central source model identifies the marked
definition; the tool then updates that definition and the declaration in the
owning class header as one transaction.

Dry-run is the default.  Any stale type, missing declaration, overload-like
ambiguity, constructor/destructor, or non-method claim rejects the entire plan
before a file is written.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

from tools.common.repo import repo_root_from_file
from tools.source_model import build_model


@dataclass(frozen=True)
class Replacement:
    path: Path
    line_index: int
    before: str
    after: str
    address: int
    role: str


def _type_pattern(type_name: str) -> str:
    return r"\s+".join(re.escape(part) for part in type_name.split())


def _replace_return(line: str, *, prefix_name: str, method_name: str,
                    old_type: str, new_type: str) -> str | None:
    pattern = re.compile(
        rf"^(?P<prefix>\s*(?:(?:virtual|static|inline)\s+)*)"
        rf"{_type_pattern(old_type)}(?P<suffix>\s+{re.escape(prefix_name + method_name)}\s*\()"
    )
    match = pattern.search(line)
    if not match:
        return None
    return line[:match.start()] + match.group("prefix") + new_type + match.group("suffix") + line[match.end():]


def plan_replacements(repo_root: Path, addresses: list[int], *, old_type: str,
                      new_type: str) -> list[Replacement]:
    model = build_model(repo_root)
    planned: list[Replacement] = []

    for address in addresses:
        claim = model.functions.get(address)
        if claim is None:
            raise ValueError(f"0x{address:08x}: no source-owned function claim")
        if claim.kind != "FUNCTION":
            raise ValueError(f"0x{address:08x}: {claim.kind} claim is not a manual definition")
        if "::" not in claim.name:
            raise ValueError(f"0x{address:08x}: {claim.name or '<unparsed>'} is not a class method")

        class_name, method_name = claim.name.rsplit("::", 1)
        if method_name.lstrip("~") == class_name.rsplit("::", 1)[-1]:
            raise ValueError(f"0x{address:08x}: constructors/destructors have no return type")

        definition = repo_root / claim.file
        definition_lines = definition.read_text(encoding="utf-8").splitlines(keepends=True)
        definition_index = claim.line
        if definition_index >= len(definition_lines):
            raise ValueError(f"0x{address:08x}: definition is missing after {claim.file}:{claim.line}")
        replaced = _replace_return(
            definition_lines[definition_index], prefix_name=f"{class_name}::",
            method_name=method_name, old_type=old_type, new_type=new_type)
        if replaced is None:
            raise ValueError(
                f"0x{address:08x}: expected return type {old_type!r} at "
                f"{claim.file}:{definition_index + 1}")
        planned.append(Replacement(
            definition, definition_index, definition_lines[definition_index], replaced,
            address, "definition"))

        header = repo_root / "include" / "game" / f"{class_name.rsplit('::', 1)[-1]}.h"
        if not header.is_file():
            raise ValueError(f"0x{address:08x}: expected owning header {header.relative_to(repo_root)}")
        header_lines = header.read_text(encoding="utf-8").splitlines(keepends=True)
        header_matches: list[tuple[int, str]] = []
        for index, line in enumerate(header_lines):
            candidate = _replace_return(
                line, prefix_name="", method_name=method_name,
                old_type=old_type, new_type=new_type)
            if candidate is not None:
                header_matches.append((index, candidate))
        if len(header_matches) != 1:
            raise ValueError(
                f"0x{address:08x}: expected one {old_type} declaration for {method_name} in "
                f"{header.relative_to(repo_root)}, found {len(header_matches)}")
        header_index, header_after = header_matches[0]
        planned.append(Replacement(
            header, header_index, header_lines[header_index], header_after,
            address, "declaration"))

    locations = [(item.path, item.line_index) for item in planned]
    if len(locations) != len(set(locations)):
        raise ValueError("plan selects the same declaration or definition more than once")
    return planned


def apply_replacements(replacements: list[Replacement]) -> None:
    by_path: dict[Path, list[Replacement]] = {}
    for replacement in replacements:
        by_path.setdefault(replacement.path, []).append(replacement)

    for path, path_replacements in by_path.items():
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        for replacement in path_replacements:
            if lines[replacement.line_index] != replacement.before:
                raise ValueError(f"{path}:{replacement.line_index + 1}: file changed after planning")
            lines[replacement.line_index] = replacement.after
        path.write_text("".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="old_type", required=True, help="Exact current return type")
    parser.add_argument("--to", dest="new_type", required=True, help="Reviewed replacement return type")
    parser.add_argument("--apply", action="store_true", help="Write the fully validated plan")
    parser.add_argument("addresses", nargs="+", help="Owned function addresses")
    args = parser.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=2)
    addresses = [int(value, 0) for value in args.addresses]
    replacements = plan_replacements(
        repo_root, addresses, old_type=args.old_type, new_type=args.new_type)
    for replacement in replacements:
        rel = replacement.path.relative_to(repo_root)
        print(
            f"0x{replacement.address:08x} {replacement.role}: "
            f"{rel}:{replacement.line_index + 1}: "
            f"{replacement.before.strip()} -> {replacement.after.strip()}")
    if args.apply:
        apply_replacements(replacements)
        print(f"applied {len(replacements)} declaration/definition edits")
    else:
        print(f"dry-run: {len(replacements)} edits; re-run with --apply to write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
