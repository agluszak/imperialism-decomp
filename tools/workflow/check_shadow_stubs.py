#!/usr/bin/env python3
"""Gate: shadow stubs — non-virtual degenerate methods that hide a real vtable slot.

Defect family (bead rcb6, first seen as three TMapMgr methods removed in dee3b1b21):
a method declared NON-virtual on a vtable-carrying class, with a degenerate body
(only `(void)arg;` casts and an optional constant return), no address marker, and
live call sites. Calls to it compile to DIRECT calls into a do-nothing body where
the original dispatches through the vtable — silent dead code that no other gate
can see (no address claim, real manual body, marker-hygiene clean).

Detection (all conditions must hold):
  (a) the method's class carries a `// VTABLE:` annotation;
  (b) the definition is not claimed by any // FUNCTION/SYNTHETIC/STUB/LIBRARY
      marker and no // NOOP: annotation vouches for it;
  (c) the body is degenerate: only (void)x; statements and at most one
      `return <literal>;`;
  (d) the method has at least one call site in manual source;
  (e) the in-class declaration is non-virtual.

For the subset whose name encodes a slot (the ...Slot<HEX> convention), the class
vtable is resolved at that byte offset in config/vtable_abi_evidence.json; a
non-null original target is a HARD ERROR (the shadow provably occupies a real
slot). All other findings are hard errors too — the combination of conditions has
no known-legitimate instance; if one ever appears, fix the model or claim the
address rather than allowlisting.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

import tree_sitter_cpp
from tree_sitter import Language, Parser

from tools.common.file_scan import iter_files
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

_CPP = Language(tree_sitter_cpp.language())
VOID_CAST_RE = re.compile(rb"^\(\s*void\s*\)\s*\w+\s*;$")
MARKER_RE = re.compile(r"//\s*(?:FUNCTION|SYNTHETIC|STUB|LIBRARY|NOOP):")
VTABLE_RE = re.compile(r"//\s*VTABLE:\s*\w+\s+0x(?P<addr>[0-9a-fA-F]+)\s*\n\s*class\s+(?P<name>\w+)")
SLOT_NAME_RE = re.compile(r"Slot([0-9A-Fa-f]{1,3})$")


def parse(source: bytes):
    return Parser(_CPP).parse(source)


def is_degenerate_body(body) -> bool:
    saw_statement = False
    for child in body.named_children:
        if child.type == "comment":
            continue
        text = re.sub(rb"\s+", b" ", child.text or b"")
        if child.type == "expression_statement" and VOID_CAST_RE.match(text):
            saw_statement = True
            continue
        if child.type == "return_statement":
            expr = [c for c in child.named_children if c.type != "comment"]
            if len(expr) > 1:
                return False
            if expr and expr[0].type not in ("number_literal", "true", "false", "null"):
                return False
            saw_statement = True
            continue
        return False
    # An entirely empty body counts (the original TMapMgr shadows returned constants,
    # but `{}` is the same failure mode).
    return True or saw_statement


def vtable_classes(repo_root: Path) -> set[str]:
    classes: set[str] = set()
    for path in iter_files(["include", "src"]):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for m in VTABLE_RE.finditer(text):
            classes.add(m.group("name"))
    return classes


def virtual_declarations(repo_root: Path) -> dict[str, set[str]]:
    """class -> set of method names declared with `virtual` anywhere."""
    result: dict[str, set[str]] = defaultdict(set)
    decl_re = re.compile(r"virtual\s+[^;{()]*?(\w+)\s*\(")
    class_re = re.compile(r"class\s+(\w+)[^;{]*\{")
    for path in iter_files(["include", "src"]):
        text = path.read_text(encoding="utf-8", errors="ignore")
        # crude but adequate: attribute virtual decls to the nearest preceding class
        classes = [(m.start(), m.group(1)) for m in class_re.finditer(text)]
        for m in decl_re.finditer(text):
            owner = None
            for start, name in classes:
                if start < m.start():
                    owner = name
                else:
                    break
            if owner:
                result[owner].add(m.group(1))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--roots", nargs="+", default=["src/game", "include/game"])
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()
    repo_root = repo_root_from_file(__file__)

    vt_classes = vtable_classes(repo_root)
    virtuals = virtual_declarations(repo_root)
    abi_path = repo_root / "config" / "vtable_abi_evidence.json"
    abi = json.loads(abi_path.read_text())["classes"] if abi_path.is_file() else {}

    # Collect candidate degenerate definitions.
    candidates = []  # (class, method, rel, line)
    for path in iter_files(args.roots):
        raw = path.read_bytes()
        tree = parse(raw)
        rel = normalize_repo_relative_path(path, repo_root)
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            stack.extend(node.children)
            if node.type != "function_definition":
                continue
            declarator = node.child_by_field_name("declarator")
            body = node.child_by_field_name("body")
            if declarator is None or body is None or body.type != "compound_statement":
                continue
            text = (declarator.text or b"").decode("utf-8", "replace")
            m = re.match(r"(?:[\w:<>~]+\s+)?(\w+)::(~?\w+)\s*\(", text.strip())
            if not m:
                continue
            cls, name = m.group(1), m.group(2)
            if name.startswith("~") or name == cls:
                continue  # ctors/dtors have their own gates
            if cls not in vt_classes:
                continue
            if name in virtuals.get(cls, set()):
                continue  # declared virtual somewhere: not a shadow by this rule
            if not is_degenerate_body(body):
                continue
            # A marker/annotation only vouches for the definition it is attached to.
            # Anchor on the contiguous comment block directly above and stop at the first
            # line of code: a fixed window instead picks up a NEIGHBOUR's marker (adjacent
            # ctor/dtor pairs make that routine here) and silently exempts this body.
            preceding = raw[: node.start_byte].decode("utf-8", "replace").splitlines()
            vouched = False
            for line in reversed(preceding):
                stripped = line.strip()
                if not stripped:
                    continue
                if not stripped.startswith("//"):
                    break
                if MARKER_RE.search(stripped):
                    vouched = True
                    break
            if vouched:
                continue
            candidates.append((cls, name, rel, node.start_point[0] + 1))

    if not candidates:
        print("Shadow-stub gate passed (0 candidates).")
        return 0

    # Call-site check across manual source.
    blobs = []
    for path in iter_files(["src/game", "include/game"]):
        blobs.append((normalize_repo_relative_path(path, repo_root),
                      path.read_text(encoding="utf-8", errors="ignore")))

    errors = []
    for cls, name, rel, line in candidates:
        call_re = re.compile(r"(?:->|\.|::)" + re.escape(name) + r"\s*\(")
        sites = 0
        for blob_rel, text in blobs:
            for m in call_re.finditer(text):
                # skip the definition file's own definition line region cheaply
                sites += 1
        # subtract the definition itself (matched as Class::Name()
        sites = max(0, sites - 1)
        if sites == 0:
            continue
        slot_note = ""
        m = SLOT_NAME_RE.search(name)
        if m and cls in abi:
            byte_off = int(m.group(1), 16)
            for slot in abi[cls].get("slots", []):
                if slot.get("byte_offset") == byte_off and not slot.get("null"):
                    slot_note = (f" — vtable slot at byte 0x{byte_off:x} resolves to real "
                                 f"original code {slot.get('target')}")
                    break
        errors.append((f"{cls}::{name}",
                       f"{rel}:{line}: {cls}::{name} — non-virtual degenerate body with "
                       f"live call sites on a vtable-carrying class{slot_note}"))

    # Baseline: the known-offender set is tracked (not blessed) — each row cites the
    # bead that will fix it. New offenders (a key not in the baseline) always fail.
    baseline_path = repo_root / "config" / "baselines" / "shadow_stub_baseline.csv"
    baselined: dict[str, str] = {}
    if baseline_path.is_file():
        for row in baseline_path.read_text().splitlines():
            row = row.strip()
            if not row or row.startswith("#"):
                continue
            key, _, bead = row.partition("|")
            baselined[key.strip()] = bead.strip()

    if args.write_baseline:
        lines = ["# key|bead — shadow-stub known offenders (tools.workflow.check_shadow_stubs).",
                 "# Each is a real defect awaiting the cited bead; NEW offenders are a hard error.",
                 "# Do not add rows by hand to silence a finding — fix the shadow or claim the slot."]
        for key, _ in sorted(errors):
            lines.append(f"{key}|{baselined.get(key, 'imperialism-decomp-12k2')}")
        baseline_path.write_text("\n".join(lines) + "\n")
        print(f"Wrote shadow-stub baseline: {len(errors)} offender(s).")
        return 0

    new_offenders = [msg for key, msg in errors if key not in baselined]
    fixed = [key for key in baselined if key not in {k for k, _ in errors}]

    if not new_offenders and not fixed:
        if errors:
            print(f"Shadow-stub gate passed ({len(errors)} baselined offender(s) tracked to "
                  "their beads; no new ones).")
        else:
            print(f"Shadow-stub gate passed ({len(candidates)} degenerate candidates, "
                  "none with live call sites).")
        return 0
    if fixed:
        print("Shadow-stub gate: these baselined offenders are gone — remove them from "
              "config/baselines/shadow_stub_baseline.csv (ratchet down):")
        for key in sorted(fixed):
            print(f"  - {key}")
    if new_offenders:
        print("Shadow-stub gate FAILED (new silently-dead call path — hard ban):")
        for msg in sorted(new_offenders):
            print(f"  - {msg}")
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
