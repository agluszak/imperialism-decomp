#!/usr/bin/env python3
"""Read-only: walk every MFC CRuntimeClass descriptor in the binary and emit the
class oracle: true class name, object size, schema, base class, and the resolved
CreateObject address (through the ILT thunk).

This is ground truth the compiler left intact: MSVC500 MFC 4.2 CRuntimeClass is

    struct CRuntimeClass {            // 0x18 bytes
      LPCSTR m_lpszClassName;         // +0x00
      int m_nObjectSize;              // +0x04
      UINT m_wSchema;                 // +0x08 (0xffff = no schema)
      CObject* (PASCAL* m_pfnCreateObject)();  // +0x0c (0 unless DECLARE_DYNCREATE)
      CRuntimeClass* m_pBaseClass;    // +0x10
      CRuntimeClass* m_pNextClass;    // +0x14 (runtime-linked; 0 in the image)
    };

Use it to (a) verify/repair curated symbols.csv names at CreateObject addresses,
(b) validate modeled class sizes against m_nObjectSize, (c) recover inheritance
edges (m_pBaseClass chain), all without trusting Ghidra's provisional labels.

CAVEAT on (c): base_name records the IMPLEMENT_DYN* macro's second argument as the
retail programmers wrote it, which is NOT always the direct C++ base. Verified
retail skips/typos (bd 223u, 2026-07): TMapMaker names TControl (C++ base TObject),
TMilitaryUnit names TObject (C++ base TUnit), TRailAmtBar names TAmtBar (C++ base
TIndustryAmtBar), TNumberedItem names TView (C++ base TMegaPicture), TMultiplayerMgr
names TObject (C++ base TEventHandler), the six TForeignMinister personalities name
TMinister (C++ base TForeignMinister), and TRemoteMinor names ITSELF (retail
copy-paste bug, C++ base TMinor). Manual source reproduces the retail macro argument
byte-for-byte while the class declaration carries the evidence-backed C++ base, so a
header/oracle disagreement is only a defect when the IMPLEMENT macro argument
disagrees with base_name.

usage:
  rtti_class_oracle [--csv]          # table (default) or CSV to stdout
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env

IMAGE_BASE = 0x400000
CODE_LO, CODE_HI = 0x401000, 0x640000  # also bounds the GetRuntimeClass byte scan
DATA_LO, DATA_HI = 0x630000, 0x6b0000


def main() -> int:
    as_csv = "--csv" in sys.argv[1:]

    project = ghidra_env.open_project()
    consumer, program = ghidra_env.open_program(project)
    try:
        mem = program.getMemory()
        af = program.getAddressFactory().getDefaultAddressSpace()

        # Snapshot every initialized block once via safe per-byte reads is far too
        # slow; Memory.getBytes with a Java-side byte[] is the documented trap
        # (silent zeros — see search_whole_binary.py). Instead read through the
        # ByteProvider-safe route: block.getByte in bulk via getBytes into a
        # jpype JArray created *from* Java (Memory.getBytes with an array obtained
        # from jpype.JArray(JByte)(n) exhibits the bug), so we fall back to
        # findBytes-free linear getByte reads but chunked per block and cached.
        blocks = []
        for block in mem.getBlocks():
            if not block.isInitialized():
                continue
            start = block.getStart().getOffset()
            size = block.getSize()
            if start + size < DATA_LO or start > DATA_HI:
                continue
            data = bytearray(size)
            for i in range(size):
                data[i] = block.getByte(block.getStart().add(i)) & 0xFF
            blocks.append((start, bytes(data)))

        def read(addr: int, n: int) -> bytes | None:
            for start, data in blocks:
                if start <= addr and addr + n <= start + len(data):
                    off = addr - start
                    return data[off:off + n]
            return None

        def dword(addr: int) -> int | None:
            b = read(addr, 4)
            return int.from_bytes(b, "little") if b else None

        def cstr(addr: int, limit: int = 64) -> str | None:
            b = read(addr, limit)
            if not b:
                return None
            end = b.find(0)
            if end <= 0:
                return None
            try:
                s = b[:end].decode("ascii")
            except UnicodeDecodeError:
                return None
            return s

        def plausible_name(s: str | None) -> bool:
            if not s or not (2 <= len(s) <= 48):
                return False
            if not (s[0].isalpha() or s[0] == "_"):
                return False
            return all(c.isalnum() or c == "_" for c in s)

        def looks_like_descriptor(addr: int) -> dict | None:
            raw = [dword(addr + i * 4) for i in range(6)]
            if any(v is None for v in raw):
                return None
            vals: list[int] = [v for v in raw if v is not None]
            namep, size, schema, pfn, base, nxt = vals
            if not (DATA_LO <= namep <= DATA_HI):
                return None
            if not (4 <= size <= 0x20000):
                return None
            if schema != 0xFFFF and schema > 0x8000:
                return None
            if pfn and not (CODE_LO <= pfn <= CODE_HI):
                return None
            if base and not (DATA_LO <= base <= DATA_HI):
                return None
            if nxt not in (0,) and not (DATA_LO <= nxt <= DATA_HI):
                return None
            name = cstr(namep)
            if not plausible_name(name):
                return None
            return {"addr": addr, "name": name, "size": size, "schema": schema,
                    "pfn": pfn, "base": base}

        # Pass 1: candidates at every 4-byte alignment in the data range.
        candidates = {}
        for start, data in blocks:
            lo = max(start, DATA_LO)
            hi = min(start + len(data), DATA_HI)
            addr = (lo + 3) & ~3
            while addr + 0x18 <= hi:
                d = looks_like_descriptor(addr)
                if d:
                    candidates[addr] = d
                addr += 4

        # Pass 2: keep candidates that participate in a base chain (their base is a
        # candidate, or another candidate uses them as base) or that CObject-root.
        referenced_as_base = {d["base"] for d in candidates.values() if d["base"]}
        keep = {}
        for addr, d in candidates.items():
            if d["base"] in candidates or addr in referenced_as_base or d["base"] == 0:
                keep[addr] = d

        # Resolve ILT jmp thunks for pfnCreateObject via instruction bytes.
        def resolve_thunk(addr: int) -> int:
            if not addr:
                return 0
            try:
                b = mem.getByte(af.getAddress(addr)) & 0xFF
                if b == 0xE9:
                    rel = int.from_bytes(
                        bytes((mem.getByte(af.getAddress(addr + 1 + i)) & 0xFF)
                              for i in range(4)), "little", signed=True)
                    return addr + 5 + rel
            except Exception:
                pass
            return addr

        # GetRuntimeClass bodies are `MOV EAX, <descriptor>; RET` (B8 xx xx xx xx C3):
        # find each descriptor's unique hit in the code range (0 = none, -1 = ambiguous).
        import jpype

        monitor = jpype.JClass("ghidra.util.task.TaskMonitor").DUMMY
        JByte = jpype.JArray(jpype.JByte)

        def find_getruntimeclass(descriptor: int) -> int:
            patt = bytes([0xB8]) + descriptor.to_bytes(4, "little") + bytes([0xC3])
            pattern = JByte(6)
            for i, b in enumerate(patt):
                pattern[i] = jpype.JByte(b if b < 128 else b - 256)
            hits = []
            addr = af.getAddress(CODE_LO)
            end = af.getAddress(CODE_HI)
            while True:
                found = mem.findBytes(addr, end, pattern, None, True, monitor)
                if found is None:
                    break
                hits.append(found.getOffset())
                if len(hits) > 1:
                    return -1
                addr = found.add(1)
            return hits[0] if hits else 0

        rows = []
        for addr in sorted(keep):
            d = keep[addr]
            base_name = keep.get(d["base"], {}).get("name", "") if d["base"] else ""
            rows.append((addr, d["name"], d["size"], d["schema"],
                         d["pfn"], resolve_thunk(d["pfn"]), d["base"], base_name,
                         find_getruntimeclass(addr)))

        if as_csv:
            print("descriptor,name,object_size,schema,createobject_thunk,createobject,base_descriptor,base_name,getruntimeclass")
            for r in rows:
                print(f"{r[0]:#x},{r[1]},{r[2]:#x},{r[3]:#x},{r[4]:#x},{r[5]:#x},{r[6]:#x},{r[7]},{r[8]:#x}")
        else:
            for r in rows:
                pfn = f"{r[4]:#x}->{r[5]:#x}" if r[4] else "-"
                grc = f"{r[8]:#x}" if r[8] > 0 else ("multi" if r[8] < 0 else "-")
                print(f"{r[0]:#010x}  {r[1]:<36} size={r[2]:<#8x} create={pfn:<22} "
                      f"getrtc={grc:<12} base={r[7] or '-'}")
            print(f"total descriptors: {len(rows)}")
        return 0
    finally:
        program.release(consumer)
        project.close()


if __name__ == "__main__":
    sys.exit(main())
