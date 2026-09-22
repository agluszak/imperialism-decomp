#!/usr/bin/env python3
"""UI factory widget-class fidelity floor.

Each generated factory TU (`build-*/generated/ui/turn_event_dialog_factory_*.cpp`)
constructs a set of widgets whose classes must match retail exactly. reccmp
similarity cannot express this (the emitters decompose into different helpers),
so this check compares a semantic fingerprint per factory: the multiset of
widget classes, resolved on the retail side by the vtable each constructor
installs — immune to Ghidra naming and codegen decomposition.

Retail extraction, per factory body (capstone disasm):

  * `call` to a ctor that stores a known vftable -> widget of that class.
    The last vftable store wins (leaf ctors overwrite the base store).
  * A vftable store in the factory body right after a ctor call reassigns the
    widget (retail inlines empty derived ctors, e.g. TTradeBookView).
  * Depth-1 recursion into non-widget callees (`..._Impl_At...` splits).

Known structural equivalences (not widget gaps):

  * `TRightLeftView` in generated code = retail `TSidewaysArrow` placeholders;
    Windows replaces them in DoPostCreate (node_class_substitutions rows with
    `construction: post_create` in config/ui_platform_deltas.yml).
  * A few container `TView`s are retail member-embedded inside other widgets
    rather than heap-constructed in the factory; generated code news them
    (allocation shape is a documented generator decision).

Gate mode fails on any unexplained class multiset difference.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path

import yaml
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

from tools.common.repo import repo_root_from_file


class RetailImage:
    def __init__(self, path: Path):
        self.data = path.read_bytes()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        nsec = struct.unpack_from("<H", self.data, pe + 6)[0]
        optsz = struct.unpack_from("<H", self.data, pe + 20)[0]
        imagebase = struct.unpack_from("<I", self.data, pe + 24 + 28)[0]
        self.sections = []
        for i in range(nsec):
            off = pe + 24 + optsz + i * 40
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", self.data, off + 8)
            self.sections.append((imagebase + vaddr, vsize, roff, rsize))

    def read(self, va: int, n: int) -> bytes:
        for vaddr, vsize, roff, rsize in self.sections:
            if vaddr <= va < vaddr + vsize:
                return self.data[roff + va - vaddr : roff + va - vaddr + n]
        return b""


class WidgetFingerprint:
    """Multiset of widget classes (by retail vftable identity) per factory."""

    def __init__(self, image: RetailImage, syms: dict[int, str], sizes: dict[int, int],
                 vtables: dict[int, str]):
        self.image = image
        self.syms = syms
        self.sizes = sizes
        self.vtables = vtables
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self._vt_cache: dict[int, int | None] = {}
        self._seen_impl: set[int] = set()

    def resolve_thunk(self, addr: int, depth: int = 0) -> int:
        if depth > 3:
            return addr
        b = self.image.read(addr, 5)
        if len(b) >= 5 and b[0] == 0xE9:
            return self.resolve_thunk((addr + 5 + struct.unpack("<i", b[1:5])[0]) & 0xFFFFFFFF, depth + 1)
        return addr

    def ctor_vtable(self, addr: int) -> int | None:
        """Last vftable stored by the callee, or None if it installs none."""
        if addr in self._vt_cache:
            return self._vt_cache[addr]
        size = min(self.sizes.get(addr, 400), 2000)
        found = None
        for ins in self.md.disasm(self.image.read(addr, size), addr):
            if ins.mnemonic == "mov" and len(ins.operands) == 2:
                src = ins.operands[1]
                if src.type == X86_OP_IMM and src.imm in self.vtables:
                    found = src.imm
            elif ins.mnemonic == "ret":
                break
            elif (
                ins.mnemonic == "jmp"
                and ins.operands
                and ins.operands[0].type == X86_OP_IMM
                and not (addr <= ins.operands[0].imm < addr + size)
            ):
                break  # tail call: linear scan would run into the callee
        self._vt_cache[addr] = found
        return found

    def factory_widgets(self, addr: int, size: int, depth: int = 0) -> list[int]:
        """Vftable addrs for every widget the body constructs (direct calls)."""
        insns = list(self.md.disasm(self.image.read(addr, size), addr))
        out: list[int] = []
        i = 0
        while i < len(insns):
            ins = insns[i]
            i += 1
            if ins.mnemonic != "call" or ins.operands[0].type != X86_OP_IMM:
                continue
            tgt = self.resolve_thunk(ins.operands[0].imm)
            vt = self.ctor_vtable(tgt)
            if vt:
                # Inline-empty-ctor pattern: the leaf vftable store lands in
                # this body right after the base ctor call.
                leaf = None
                for ni in insns[i : i + 14]:
                    if ni.mnemonic == "call":
                        break
                    if ni.mnemonic == "mov" and len(ni.operands) == 2:
                        d, s2 = ni.operands
                        if (
                            d.type == X86_OP_MEM
                            and s2.type == X86_OP_IMM
                            and s2.imm in self.vtables
                        ):
                            leaf = s2.imm
                out.append(leaf if leaf else vt)
            elif depth == 0 and tgt in self.syms and tgt not in self._seen_impl:
                # Compiler split-out `..._Impl_At...` bodies construct more widgets.
                self._seen_impl.add(tgt)
                out.extend(self.factory_widgets(tgt, self.sizes.get(tgt, 0), 1))
        return out


def load_reclass_equivalent(repo_root: Path) -> dict[str, str]:
    """generated class -> retail factory class for declared post-create swaps.

    `node_class_substitutions` rows with `construction: post_create` mean the
    retail factory constructs the Mac class and a later DoPostCreate swaps in
    the Windows class; generated factories emit the final class directly, so
    the fingerprint maps the emitted class back to what retail's factory built.
    """
    data = yaml.safe_load(
        (repo_root / "config/ui_platform_deltas.yml").read_text(encoding="utf-8")
    )
    return {
        str(row["windows_class"]): str(row["mac_class"])
        for row in data.get("node_class_substitutions") or []
        if row.get("construction") == "post_create"
    }
# Retail embeds these container views as members inside other widgets; the
# emitter news them separately (documented generator freedom).
EMBEDDED_TVIEW_ALLOWANCE = {
    0x4295A0: 1,  # BuildTurnEventDialogResourcesForEvent547Or7D8
    0x430C50: 2,  # InitializeDealBookScreenControlsAndCommandTags
    0x4538A0: 4,  # InitializeGameSetupScreenControlsAndModeTags
    0x4601B0: 1,  # InitializeTradeScreenBitmapControls
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--original", required=True, type=Path, help="retail Imperialism.exe")
    ap.add_argument("--build-dir", required=True, type=Path)
    args = ap.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=2)
    build_dir = args.build_dir if args.build_dir.is_absolute() else repo_root / args.build_dir
    gen_ui = build_dir / "generated" / "ui"
    manifest = json.loads((gen_ui / "_manifest.json").read_text())

    syms: dict[int, str] = {}
    sizes: dict[int, int] = {}
    for row in csv.DictReader(open(build_dir / "generated" / "symbols.csv"), delimiter="|"):
        try:
            addr = int(row["address"], 16)
        except ValueError:
            continue
        syms[addr] = row["name"]
        if row["size"]:
            sizes[addr] = int(row["size"])
    vtables = {
        int(v["address"], 16): v["class"]
        for v in json.loads((build_dir / "generated" / "source_model.json").read_text())["vtables"]
    }
    vt_name = {a: n for a, n in vtables.items()}

    reclass_equivalent = load_reclass_equivalent(repo_root)
    fp = WidgetFingerprint(RetailImage(args.original), syms, sizes, vtables)

    failures = []
    for ent in manifest["files"]:
        addr = int(ent["address"], 16)
        retail = Counter(
            vt_name.get(v, hex(v)) for v in fp.factory_widgets(addr, sizes.get(addr, 0))
        )
        src = (gen_ui / ent["file"]).read_text()
        recomp = Counter(
            reclass_equivalent.get(c, c) for c in re.findall(r"new (\w+)\s*\(", src)
        )
        # Embedded container views: allow the recorded TView slack only.
        embedded = EMBEDDED_TVIEW_ALLOWANCE.get(addr, 0)
        recomp_adjusted = Counter(recomp)
        if embedded:
            recomp_adjusted.subtract({"TView": embedded})
            recomp_adjusted += Counter()  # drop zeros
        missing = retail - recomp_adjusted
        extra = recomp_adjusted - retail
        if missing or extra:
            failures.append((ent["name"], ent["address"], missing, extra))
            print(f"FAIL {ent['name']} @ {ent['address']}")
            if missing:
                print(f"  retail-only: {dict(missing)}")
            if extra:
                print(f"  recomp-only: {dict(extra)}")

    if failures:
        print(f"\n{len(failures)}/{len(manifest['files'])} factories diverge", file=sys.stderr)
        return 1
    print(f"{len(manifest['files'])} factories: widget-class fingerprints match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
