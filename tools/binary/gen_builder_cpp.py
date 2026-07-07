#!/usr/bin/env python3
"""Generate compact-vocabulary C++ for a turn-event screen-builder region.

Extends tools/binary/decode_builder.py from a decode *aid* to a code *generator*:
walks the original binary over [start, end), recognizes the widget-block helper
vocabulary (see decomp-loop heuristics note 36) and emits ready-to-review C++
statements. Anything unrecognized is emitted as a `// RAW addr insn` comment so
the porter can hand-fix expanded-idiom blocks; the output is a porting draft,
never committed verbatim.

usage: uv run python -m tools.binary.gen_builder_cpp 0xSTART 0xEND
       (or `just gen-builder 0xSTART 0xEND`)
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

import capstone

from tools.binary.pe import OriginalImage, load_symbol_names
from tools.common.repo import repo_root_from_file

REPO_ROOT = repo_root_from_file(__file__)

# Real ctor body address -> (class name, expected object size). Sizes are a
# sanity check against the preceding `push n; call operator new`.
CTORS: dict[int, str] = {
    0x48A8E0: "TView",
    0x48EFC0: "TPicture",
    0x48F890: "TStaticText",
    0x429330: "TInfoBarText",
    0x429500: "TNumberText",
    0x48F810: "TPictureText",
    0x5707F0: "TPictureButton",
    0x5715A0: "TUpDownPictureButton",
    0x573A20: "TSliderPicture",
    0x583B50: "TSidewaysArrow",
    0x584480: "TTradeOrderPicture",
    0x584E20: "TToolBarCluster",
    0x5870B0: "TTradeCluster",
    0x58AEF0: "TTraderAmtBar",
    0x5B4FD0: "TMyNumberText",
    0x5B5590: "TDropShadowText",
    0x5B5910: "TDropShadowNumberText",
    0x5BA720: "TTradeScreenPicture",
    0x491400: "TCluster",
    0x48A960: "TGameWindow",
    0x48F930: "TDeluxeText",
    0x5B7640: "TScrollView",
    0x48A920: "TWindow",
}

# cdecl helper vocabulary: real target -> (emitted name, arg count).
HELPERS: dict[int, tuple[str, int]] = {
    0x41B210: ("RegisterUiResourceEntry", 11),
    0x41B3A0: ("SetUiResourceStateFlags", 2),
    0x41B3D0: ("SetUiResourceContextPictureId", 1),
    0x41B400: ("SetUiResourceContextStringCode", 1),
    0x41B450: ("SetUiResourceLayoutValues", 5),
    0x41B570: ("SetUiResourceContextMaxCharCount", 1),
    0x41B5A0: ("SetUiResourceContextNumberValueAndRange", 3),
    0x427060: ("ReplaceUiResourceContextPairBuffer", 2),
    0x41B5F0: ("ClearUiResourceContext", 0),
    0x41B610: ("PopUiResourcePoolNode", 1),
}

OP_NEW = 0x606F73
OP_DELETE = 0x606FAF
BIND_TEXT = 0x41B490
STYLEREF_CTOR = 0x4270E0
ADDTAIL = 0x479B00
REMOVETAIL = 0x479A80
G_HEAD = 0x6A141C
G_CONTEXT = 0x6A1420
G_STACK = 0x6A13E0

# Expanded-idiom thiscall targets -> (method, stack arg count).
THISCALLS: dict[int, tuple[str, int]] = {
    0x48AA60: ("InitializeUiResourceEntryFrameAndParent", 7),
    0x48C900: ("PropagateUiResourceContextRecursive", 1),
    0x41B420: ("Reset", 0),
}

# Context vtable slot byte offsets -> (method, arg count, receiver cast).
VSLOTS: dict[int, tuple[str, int, str]] = {
    0xA4: ("SetEnabled", 2, "TView"),
    0xA8: ("SetState", 2, "TView"),
    0x1C8: ("SetPictureResourceIdAndRefresh", 2, "TPicture"),
    0x1E4: ("SetControlValue", 2, "TNumberText"),
}


def load_tag_names() -> dict[int, str]:
    tags: dict[int, str] = {}
    hdr = REPO_ROOT / "include" / "game" / "ui_control_tags.h"
    for m in re.finditer(r"const unsigned int (k\w+) = (0x[0-9a-fA-F]+)", hdr.read_text()):
        tags.setdefault(int(m.group(2), 16), m.group(1))
    return tags


def load_string_globals() -> dict[int, str]:
    src = (REPO_ROOT / "src" / "game" / "global_data_tables.cpp").read_text().splitlines()
    out: dict[int, str] = {}
    for i, line in enumerate(src):
        m = re.match(r"// GLOBAL: IMPERIALISM (0x[0-9a-fA-F]+)", line)
        if m and i + 1 < len(src):
            d = re.match(r"(?:extern )?\w[\w ]*\**\s*(g_\w+)", src[i + 1].strip())
            if d:
                out[int(m.group(1), 16)] = d.group(1)
    return out


def fmt_tag(value: int, tags: dict[int, str]) -> str:
    if value in tags:
        return tags[value]
    raw = struct.pack("<I", value & 0xFFFFFFFF)
    if all(0x20 <= b < 0x7F for b in raw):
        return f"0x{value:08x} /* '{raw[::-1].decode()}' */"
    return fmt_int(value)


def fmt_int(value: int) -> str:
    if isinstance(value, str):
        return value
    if -9 <= value <= 9:
        return str(value)
    if value < 0:
        return f"-0x{-value:x}"
    return f"0x{value:x}"


class Gen:
    def __init__(self, image: OriginalImage):
        self.image = image
        self.names = load_symbol_names()
        self.tags = load_tag_names()
        self.strings = load_string_globals()
        self.lines: list[str] = []
        self.pending: list[object] = []  # push stack, source order reversed
        # builder-function register conventions: ESI is xor'd to 0 in the prologue
        # and used as the zero constant; EDI holds -1 for the EH-state restores
        self.regs: dict[str, object] = {"esi": 0, "edi": -1}
        self.widget_n = 0
        self.widget_names: dict[str, str] = {}  # placeholder -> final name
        self.cur_widget: str | None = None
        self.styleref: object | None = None
        self.new_size: int | None = None

    def emit(self, text: str) -> None:
        self.lines.append(text)

    def raw(self, ins) -> None:
        self.emit(f"// RAW {ins.address:#x}  {ins.mnemonic} {ins.op_str}")

    def resolve(self, reg: str) -> object:
        return self.regs.get(reg, f"/*{reg}*/")

    def arg(self, v: object) -> str:
        if isinstance(v, int):
            if v in self.strings:
                return self.strings[v]
            return fmt_int(v)
        return str(v)

    def tag_arg(self, v: object) -> str:
        if isinstance(v, int):
            return fmt_tag(v, self.tags)
        return str(v)

    def pop_args(self, n: int) -> list[object]:
        if len(self.pending) < n:
            missing = n - len(self.pending)
            args = ["/*?*/"] * missing + self.pending
            self.pending = []
            return args
        args = self.pending[-n:]
        del self.pending[-n:]
        return args

    def run(self, start: int, end: int) -> str:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = False
        fo = self.image.va_to_file_offset(start)
        insns = []
        covered = start
        while covered < end:
            chunk = list(md.disasm(self.image.data[self.image.va_to_file_offset(covered) : fo + (end - start)], covered))
            if not chunk:
                covered += 1
                continue
            insns += chunk
            covered = chunk[-1].address + chunk[-1].size
        i = 0
        while i < len(insns):
            i = self.step(insns, i)
        # post-pass: substitute final widget names
        text = "\n".join(self.lines)
        for ph, final in self.widget_names.items():
            text = text.replace(ph, final)
        return text

    def step(self, insns, i: int) -> int:
        ins = insns[i]
        text = f"{ins.mnemonic} {ins.op_str}"

        m = re.fullmatch(r"push (-?(?:0x)?[0-9a-f]+)", text)
        if m:
            self.pending.append(int(m.group(1), 0))
            return i + 1
        m = re.fullmatch(r"push (e..)", text)
        if m:
            self.pending.append(self.resolve(m.group(1)))
            return i + 1

        m = re.fullmatch(r"xor (e..), \1", text)
        if m:
            # the failed-`new` join (`jz L1 ... jmp L2 / L1: xor r,r / L2:`) must not
            # clobber the widget register the fallthrough path just set
            prev = insns[i - 1] if i > 0 else None
            cur = self.regs.get(m.group(1))
            if not (
                prev is not None
                and prev.mnemonic == "jmp"
                and isinstance(cur, str)
                and cur.startswith("__W")
            ):
                self.regs[m.group(1)] = 0
            return i + 1
        m = re.fullmatch(r"or (e..), 0xffffffff", text)
        if m:
            self.regs[m.group(1)] = -1
            return i + 1
        m = re.fullmatch(r"mov (e..), (-?(?:0x)?[0-9a-f]+)", text)
        if m:
            self.regs[m.group(1)] = int(m.group(2), 0)
            return i + 1
        m = re.fullmatch(r"mov (e..), (e..)", text)
        if m:
            if m.group(1) == "ecx" and m.group(2) == "esp":
                # `push theme; push ecx; mov ecx, esp` reserves the by-value
                # TUiStyleRef slot the converting ctor then constructs in place
                if self.pending:
                    self.pending[-1] = "STYLEREF_SLOT"
                return i + 1
            self.regs[m.group(1)] = self.resolve(m.group(2))
            return i + 1
        m = re.fullmatch(r"mov (e..), dword ptr \[0x6a1420\]", text)
        if m:
            self.regs[m.group(1)] = "CONTEXT"
            return i + 1
        m = re.fullmatch(r"mov (e..), dword ptr \[(e..)\]", text)
        if m:
            # vtable load of a tracked object pointer — keep receiver identity
            self.regs[m.group(1)] = ("VTBL", self.resolve(m.group(2)))
            return i + 1
        m = re.fullmatch(r"mov dword ptr \[0x6a141c\], (e..|(?:0x)?[0-9a-f]+)", text)
        if m:
            src = m.group(1)
            v = self.resolve(src) if src.startswith("e") else int(src, 0)
            self.emit(f"g_pUiResourceHead = {self.arg(v)};")
            return i + 1
        m = re.fullmatch(r"mov dword ptr \[0x6a1420\], (e..|(?:0x)?[0-9a-f]+)", text)
        if m:
            src = m.group(1)
            v = self.resolve(src) if src.startswith("e") else int(src, 0)
            self.emit(f"g_pUiResourceContext = {self.arg(v)};")
            return i + 1
        m = re.fullmatch(r"mov dword ptr \[(e..) \+ 0x84\], (e..)", text)
        if m and self.resolve(m.group(1)) == "CONTEXT":
            v = self.resolve(m.group(2))
            self.emit(
                "static_cast<TCluster*>(g_pUiResourceContext)->field84 = "
                f"static_cast<int>({self.tag_arg(v)});"
            )
            return i + 1

        m = re.fullmatch(r"call (0x[0-9a-f]+)", text)
        if m:
            target = self.image.resolve_thunk(int(m.group(1), 16))
            return self.handle_call(ins, target, i)

        m = re.fullmatch(r"call dword ptr \[(e..) \+ (0x[0-9a-f]+)\]", text)
        if m:
            slot = int(m.group(2), 16)
            vt = self.resolve(m.group(1))
            recv = vt[1] if isinstance(vt, tuple) and vt[0] == "VTBL" else self.resolve("ecx")
            if slot in VSLOTS:
                name, argc, cast = VSLOTS[slot]
                args = ", ".join(self.arg(a) for a in reversed(self.pop_args(argc)))
                if recv == "CONTEXT":
                    self.emit(f"static_cast<{cast}*>(g_pUiResourceContext)->{name}({args});")
                else:
                    self.emit(f"{recv}->{name}({args});")
                return i + 1
            self.raw(ins)
            self.pending = []
            return i + 1

        if ins.mnemonic in (
            "cmp",
            "test",
            "jz",
            "jnz",
            "je",
            "jne",
            "jmp",
            "add",
            "sub",
            "lea",
            "nop",
            "ret",
            "pop",
            "movsx",
            "dec",
            "inc",
        ):
            # add esp/new-null-check scaffolding; jmp is surfaced for review
            if ins.mnemonic in ("jmp", "ret", "movsx", "lea"):
                self.raw(ins)
            return i + 1

        m = re.fullmatch(r"mov dword ptr \[esp \+ 0x[0-9a-f]+\], (e..|-?(?:0x)?[0-9a-f]+)", text)
        if m:
            return i + 1  # EH-state / new-temp spills

        self.raw(ins)
        return i + 1

    def handle_call(self, ins, target: int, i: int) -> int:
        if target == OP_NEW:
            self.new_size = self.pop_args(1)[0]
            return i + 1
        if target == OP_DELETE:
            self.pop_args(1)
            self.emit("// RAW operator delete on pending value (field48 replace idiom)")
            return i + 1
        if target in CTORS:
            cls = CTORS[target]
            self.widget_n += 1
            ph = f"__W{self.widget_n}__"
            size = fmt_int(self.new_size) if self.new_size is not None else "?"
            self.emit(f"{cls}* {ph} = new {cls}();  // object size {size}")
            self.new_size = None
            # constructed object flows through eax (and often a callee-saved reg)
            self.regs["eax"] = ph
            self.cur_widget = ph
            self.widget_names.setdefault(ph, f"w{self.widget_n}")
            return i + 1
        if target == STYLEREF_CTOR:
            self.styleref = self.pop_args(1)[0]
            return i + 1
        if target == BIND_TEXT:
            args = self.pop_args(6)
            theme: object = "/*?*/"
            if self.pending and self.pending[-1] == "STYLEREF_SLOT":
                self.pending.pop()
                if self.pending:
                    theme = self.pending.pop()
            group, variant, txt, mode, flag, ptsize = reversed(args)
            sr = self.arg(self.styleref) if self.styleref is not None else "/*?*/"
            self.emit(
                f"BindUiResourceTextAndStyle({self.arg(group)}, {self.arg(variant)}, "
                f"{self.arg(txt)}, {self.arg(mode)}, {self.arg(flag)}, {self.arg(ptsize)}, "
                f"{sr}, {self.arg(theme)});"
            )
            self.styleref = None
            return i + 1
        if target == REMOVETAIL:
            self.emit("PopUiWidgetBuildStackNode();")
            return i + 1
        if target == ADDTAIL:
            node = self.pop_args(1)[0]
            self.emit(f"PushUiWidgetBuildStackNode({self.arg(node)});")
            return i + 1
        if target in THISCALLS:
            name, argc = THISCALLS[target]
            recv = self.resolve("ecx")
            args = ", ".join(self.arg(a) for a in reversed(self.pop_args(argc)))
            self.emit(f"{self.arg(recv)}->{name}({args});")
            return i + 1
        if target in HELPERS:
            name, argc = HELPERS[target]
            args = list(reversed(self.pop_args(argc)))
            if name == "RegisterUiResourceEntry":
                name_tag, ctl_tag, widget, x, y, w, h, state, enabled, owner, f3c = args
                # widget-local naming from the control tag
                if isinstance(widget, str) and widget.startswith("__W"):
                    base = None
                    if isinstance(ctl_tag, int):
                        raw = struct.pack("<I", ctl_tag)[::-1].decode("latin1")
                        base = re.sub(r"\W", "_", raw.strip()).lower()
                    if base:
                        n = widget.strip("_")[1:]
                        self.widget_names[widget] = f"{base}_{n}"
                rendered = (
                    f"RegisterUiResourceEntry({self.tag_arg(name_tag)}, {self.tag_arg(ctl_tag)}, "
                    f"{self.arg(widget)}, {self.arg(x)}, {self.arg(y)}, {self.arg(w)}, "
                    f"{self.arg(h)}, {self.arg(state)}, {self.arg(enabled)}, "
                    f"{self.tag_arg(owner)}, {self.arg(f3c)});"
                )
                self.emit("")
                self.emit(rendered)
                return i + 1
            self.emit(f"{name}({', '.join(self.arg(a) for a in args)});")
            return i + 1
        name = self.names.get(target, f"sub_{target:x}")
        argstr = ", ".join(self.arg(a) for a in reversed(self.pending))
        self.emit(f"// RAW {ins.address:#x}  call {name}@{target:#x}  pending~({argstr})")
        self.pending = []
        return i + 1


def main() -> int:
    argv = sys.argv[1:]
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    start, end = int(argv[0], 16), int(argv[1], 16)
    gen = Gen(OriginalImage())
    print(gen.run(start, end))
    return 0


if __name__ == "__main__":
    sys.exit(main())
