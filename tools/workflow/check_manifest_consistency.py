#!/usr/bin/env python3
"""`just manifest-gate`: keep headers and per-class manifests in sync.

For every header that carries a generated block (``// === BEGIN GENERATED (X) ===``)
this asserts:

  1. the block matches a *fresh* render of ``config/classes/X.yml`` — so the header
     can never silently drift from the manifest (run ``just gen-class X`` to fix);
  2. the manifest exists; and
  3. the hand-owned ``// VTABLE:`` address in the header agrees with the manifest's
     ``generated.vtable_addr`` (a stale annotation would mispair the vtable).

Check-only; it never edits files. It only inspects classes that have opted into
source modeling (a header with a generated block), not the full manifest set.
"""

from __future__ import annotations

import argparse
import re

from tools.common.class_manifest import hex8, load_manifest
from tools.common.file_scan import iter_files
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file
from tools.workflow.gen_class import (
    find_block,
    manifest_path,
    render_generated_block,
)

BEGIN_RE = re.compile(r"^//\s*===\s*BEGIN GENERATED \((?P<cls>\w+)\)")
VTABLE_RE = re.compile(r"^\s*//\s*VTABLE\s*:\s*[A-Za-z0-9_]+\s+(?P<addr>(?:0x)?[0-9a-fA-F]+)")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Check generated blocks match their manifests.")
    p.add_argument("--paths", nargs="+", default=["include/game"], help="Files/dirs to scan.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    violations: list[str] = []
    checked = 0

    for path in iter_files(args.paths):
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = normalize_repo_relative_path(path, repo_root)
        for line in text.splitlines():
            m = BEGIN_RE.match(line.rstrip())
            if not m:
                continue
            cls = m.group("cls")
            checked += 1

            mpath = manifest_path(repo_root, cls)
            if not mpath.exists():
                violations.append(f"{rel}: generated block for {cls} but no manifest {mpath.name}")
                break
            manifest = load_manifest(mpath)

            # (1) block matches a fresh render
            expected = render_generated_block(manifest).split("\n")
            found = find_block(text, cls)
            if found is None:
                violations.append(f"{rel}: malformed/again-unterminated generated block for {cls}")
                break
            start, end_idx = found
            actual = text.splitlines()[start : end_idx + 1]
            if actual != expected:
                violations.append(
                    f"{rel}: generated block for {cls} is out of date — run `just gen-class {cls} --write`"
                )

            # (3) hand-owned // VTABLE: address agrees with the manifest
            manifest_vt = manifest.get("generated", {}).get("vtable_addr")
            header_vts = {
                hex8(vm.group("addr"))
                for ln in text.splitlines()
                if (vm := VTABLE_RE.match(ln))
            }
            if manifest_vt and header_vts and hex8(manifest_vt) not in header_vts:
                violations.append(
                    f"{rel}: {cls} // VTABLE: {sorted(header_vts)} disagrees with manifest "
                    f"vtable_addr {hex8(manifest_vt)}"
                )
            break  # one generated block per header

    print(f"Manifest-consistency: checked {checked} generated block(s).")
    if violations:
        print("Manifest-consistency gate failed:")
        for v in sorted(violations):
            print(f"    - {v}")
        return 1
    print("Manifest-consistency gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
