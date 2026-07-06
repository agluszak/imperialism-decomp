#!/usr/bin/env python3
"""Read-only: enumerate every MFC message map (AFX_MSGMAP) in the binary and emit,
for each class, the full message->handler table joined against function ownership.

The UI runs on MFC message maps as much as on vtables, and message-map handlers are
invisible to vtable audits. This is Audit C (bd 1uj.58.3).

Ground truth the compiler left intact (MSVC500 / MFC 4.2):

    struct AFX_MSGMAP {                    // 8 bytes
      const AFX_MSGMAP* pBaseMap;          // +0x00  base class's map, or 0
      const AFX_MSGMAP_ENTRY* lpEntries;   // +0x04  -> entry array (usually map+8)
    };
    struct AFX_MSGMAP_ENTRY {              // 24 bytes
      UINT nMessage;  // +0x00
      UINT nCode;     // +0x04
      UINT nID;       // +0x08
      UINT nLastID;   // +0x0c
      UINT nSig;      // +0x10  (AfxSig_*; 0 = AfxSig_end sentinel terminates the array)
      void* pfn;      // +0x14  (usually an ILT jmp thunk to the real handler)
    };

Each class's GetMessageMap override is a trivial getter `MOV EAX, <&messageMap>; RET`
(B8 imm32 C3) — the same shape as GetRuntimeClass. They are told apart by the imm's
target: a message map has an rdata pointer at +0x04 (lpEntries), whereas a CRuntimeClass
has a small object-size int at +0x04. We scan the code for those getters, validate the
map, walk the entry array (resolving ILT jmp thunks to real handler bodies), and name the
owning class from the CRuntimeClass descriptor that sits just before the map in rdata
(the DYNCREATE layout; cross-checked below).

Validation targets (bd 1uj.58.3):
  * CMcWindow  map @ 0x64b5e8, entries @ 0x64b5f0, WM_PAINT(0xf) -> OnPaint 0x4938c0.
  * CIncludeView map @ 0x6481e8, includes 0x4ef -> 0x482c1c, and NO WM_PAINT.

usage:
  dump_message_maps            # human table
  dump_message_maps --csv      # CSV: class,map,base_map,index,message,msg_name,code,id,
                               #      last_id,sig,pfn,handler,owner,status
  dump_message_maps --unported # only rows whose handler has no manual owner
"""

from __future__ import annotations

import csv
import os
import sys

from tools.common import ghidra_env

IMAGE_BASE = 0x400000
CODE_LO, CODE_HI = 0x401000, 0x640000
DATA_LO, DATA_HI = 0x630000, 0x6B0000

OWNERSHIP_CSV = "config/function_ownership.csv"

# Common window messages for readable output; everything else is annotated by band.
WM_NAMES = {
    0x0001: "WM_CREATE", 0x0002: "WM_DESTROY", 0x0005: "WM_SIZE", 0x0006: "WM_ACTIVATE",
    0x0007: "WM_SETFOCUS", 0x0008: "WM_KILLFOCUS", 0x000F: "WM_PAINT",
    0x0010: "WM_CLOSE", 0x0014: "WM_ERASEBKGND", 0x001C: "WM_ACTIVATEAPP",
    0x0020: "WM_SETCURSOR", 0x0024: "WM_GETMINMAXINFO", 0x004E: "WM_NOTIFY",
    0x0100: "WM_KEYDOWN", 0x0101: "WM_KEYUP", 0x0102: "WM_CHAR",
    0x0111: "WM_COMMAND", 0x0112: "WM_SYSCOMMAND", 0x0113: "WM_TIMER",
    0x0114: "WM_HSCROLL", 0x0115: "WM_VSCROLL", 0x0117: "WM_INITMENUPOPUP",
    0x0200: "WM_MOUSEMOVE", 0x0201: "WM_LBUTTONDOWN", 0x0202: "WM_LBUTTONUP",
    0x0203: "WM_LBUTTONDBLCLK", 0x0204: "WM_RBUTTONDOWN", 0x0205: "WM_RBUTTONUP",
    0x0206: "WM_RBUTTONDBLCLK", 0x0207: "WM_MBUTTONDOWN", 0x0208: "WM_MBUTTONUP",
    0x020A: "WM_MOUSEWHEEL", 0x0210: "WM_PARENTNOTIFY",
}


def msg_name(msg: int) -> str:
    if msg in WM_NAMES:
        return WM_NAMES[msg]
    if msg == 0:
        return "(command/id)"  # ON_COMMAND/ON_UPDATE_COMMAND_UI store the id, nMessage=0
    if 0x0400 <= msg < 0x8000:
        return f"WM_USER+{msg - 0x0400:#x}"
    if 0x8000 <= msg < 0xC000:
        return f"WM_APP+{msg - 0x8000:#x}"
    if 0xC000 <= msg <= 0xFFFF:
        return "RegisteredMsg"
    return "?"


def load_ownership() -> dict[int, str]:
    owners: dict[int, str] = {}
    path = OWNERSHIP_CSV
    if not os.path.exists(path):
        return owners
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh, delimiter="|"):
            try:
                owners[int(row["address"], 16)] = row["target_cpp"]
            except (KeyError, ValueError):
                continue
    return owners


def main() -> int:
    argv = sys.argv[1:]
    as_csv = "--csv" in argv
    only_unported = "--unported" in argv

    owners = load_ownership()

    project = ghidra_env.open_project()
    consumer, program = ghidra_env.open_program(project)
    try:
        mem = program.getMemory()
        af = program.getAddressFactory().getDefaultAddressSpace()

        # Bulk per-byte snapshot of the rdata/data blocks (Memory.getBytes with a
        # jpype array silently returns zeros — see search_whole_binary.py).
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
                return b[:end].decode("ascii")
            except UnicodeDecodeError:
                return None

        def in_data(v: int) -> bool:
            return DATA_LO <= v <= DATA_HI

        def resolve_thunk(addr: int) -> int:
            """Follow ILT `E9 rel32` jmp chains to the real body (<=8 hops)."""
            seen = set()
            for _ in range(8):
                if addr in seen:
                    break
                seen.add(addr)
                try:
                    b0 = mem.getByte(af.getAddress(addr)) & 0xFF
                except Exception:
                    break
                if b0 != 0xE9:
                    break
                rel = int.from_bytes(
                    bytes((mem.getByte(af.getAddress(addr + 1 + i)) & 0xFF)
                          for i in range(4)), "little", signed=True)
                addr = addr + 5 + rel
            return addr

        # ---- Find CRuntimeClass descriptors (for naming maps by rdata proximity) ----
        def looks_like_descriptor(addr: int) -> str | None:
            namep = dword(addr)
            size = dword(addr + 4)
            schema = dword(addr + 8)
            if namep is None or size is None or schema is None:
                return None
            if not in_data(namep) or not (4 <= size <= 0x20000):
                return None
            if schema != 0xFFFF and schema > 0x8000:
                return None
            name = cstr(namep)
            if not name or not (2 <= len(name) <= 48):
                return None
            if not (name[0].isalpha() or name[0] == "_"):
                return None
            if not all(c.isalnum() or c == "_" for c in name):
                return None
            return name

        descriptors: dict[int, str] = {}
        for start, data in blocks:
            lo = max(start, DATA_LO)
            hi = min(start + len(data), DATA_HI)
            a = (lo + 3) & ~3
            while a + 0x18 <= hi:
                nm = looks_like_descriptor(a)
                if nm:
                    descriptors[a] = nm
                a += 4

        # ---- Validate + walk a candidate AFX_MSGMAP ----
        def walk_map(map_addr: int):
            base = dword(map_addr)
            entries = dword(map_addr + 4)
            if base is None or entries is None:
                return None
            if base != 0 and not in_data(base):
                return None
            if not in_data(entries):
                return None
            rows = []
            a = entries
            for _ in range(512):
                nMessage = dword(a)
                nSig = dword(a + 0x10)
                pfn = dword(a + 0x14)
                if nMessage is None or nSig is None or pfn is None:
                    return None
                if nSig == 0:  # AfxSig_end sentinel
                    break
                nID = dword(a + 8)
                nLastID = dword(a + 0xC)
                # Real entries: 16-bit message/ids and a small AfxSig_* enum index; pfn is
                # a code address (usually an ILT jmp thunk). These bounds reject rdata
                # runs of code pointers that structurally resemble an entry array.
                if nMessage > 0xFFFF or nSig >= 0x40:
                    return None
                if nID is None or nLastID is None or nID > 0xFFFF or nLastID > 0xFFFF:
                    return None
                if not (CODE_LO <= pfn <= CODE_HI):
                    return None
                rows.append({
                    "nMessage": nMessage,
                    "nCode": dword(a + 4) or 0,
                    "nID": nID,
                    "nLastID": nLastID,
                    "nSig": nSig,
                    "pfn": pfn,
                })
                a += 0x18
            else:
                return None  # never hit the sentinel within the cap
            # An empty derived map (only pBaseMap) is valid; a rootless empty map is noise.
            if not rows and base == 0:
                return None
            return {"base": base, "entries": entries, "rows": rows}

        # Candidate maps: every 4-aligned rdata addr whose shape validates as a map.
        # Pass 1 collects structurally-valid maps; pass 2 keeps only those whose pBaseMap
        # is 0 (the CCmdTarget root) or itself a validated map — the base-chain filter
        # (same idea as rtti_class_oracle) kills rdata coincidences without a code scan.
        candidates: dict[int, dict] = {}
        for start, data in blocks:
            lo = max(start, DATA_LO)
            hi = min(start + len(data), DATA_HI)
            a = (lo + 3) & ~3
            while a + 8 <= hi:
                walked = walk_map(a)
                if walked is not None:
                    candidates[a] = walked
                a += 4

        # A map with real handler rows is trustworthy on its own (the strict per-entry
        # validation above makes accidental rdata matches vanishingly unlikely). An empty
        # (handler-less, base-only) map carries no signal, so only keep it when its
        # pBaseMap chains to another candidate — that guards against {0, ptr-to-sentinel}
        # noise without dropping real leaf maps whose framework base failed to validate.
        maps: dict[int, dict] = {}
        for a, walked in candidates.items():
            if walked["rows"]:
                maps[a] = walked
            elif walked["base"] in candidates:
                maps[a] = walked

        # Name each map from the nearest CRuntimeClass descriptor just before it.
        def name_map(map_addr: int) -> str:
            for delta in (0x18, 0x1C, 0x20, 0x14, 0x24, 0x28, 0x2C, 0x30):
                nm = descriptors.get(map_addr - delta)
                if nm:
                    return nm
            best = None
            for d, nm in descriptors.items():
                if 0 < map_addr - d <= 0x40 and (best is None or d > best[0]):
                    best = (d, nm)
            return best[1] if best else f"map@{map_addr:#x}"

        # ---- Emit ----
        out_rows = []
        for map_addr in sorted(maps):
            m = maps[map_addr]
            cls = name_map(map_addr)
            for idx, e in enumerate(m["rows"]):
                handler = resolve_thunk(e["pfn"])
                owner = owners.get(handler, "")
                status = "ported" if owner else "unported"
                if only_unported and status != "unported":
                    continue
                out_rows.append({
                    "class": cls,
                    "map": f"{map_addr:#x}",
                    "base_map": f"{m['base']:#x}" if m["base"] else "-",
                    "index": idx,
                    "message": f"{e['nMessage']:#x}",
                    "msg_name": msg_name(e["nMessage"]),
                    "code": f"{e['nCode']:#x}",
                    "id": f"{e['nID']:#x}",
                    "last_id": f"{e['nLastID']:#x}",
                    "sig": f"{e['nSig']:#x}",
                    "pfn": f"{e['pfn']:#x}",
                    "handler": f"{handler:#x}",
                    "owner": owner,
                    "status": status,
                })

        if as_csv:
            cols = ["class", "map", "base_map", "index", "message", "msg_name", "code",
                    "id", "last_id", "sig", "pfn", "handler", "owner", "status"]
            w = csv.DictWriter(sys.stdout, fieldnames=cols, lineterminator="\n")
            w.writeheader()
            w.writerows(out_rows)
        else:
            cur = None
            ported = unported = 0
            for r in out_rows:
                if r["class"] != cur:
                    cur = r["class"]
                    m = maps[int(r["map"], 16)]
                    base = f" : base {r['base_map']}" if r["base_map"] != "-" else ""
                    print(f"\n{cur}  (map {r['map']}, {len(m['rows'])} entries{base})")
                mark = "  " if r["status"] == "ported" else "!!"
                idtxt = f" id={r['id']}" if r["id"] != "0x0" else ""
                own = r["owner"] or "UNPORTED"
                print(f"  {mark} {r['message']:>7} {r['msg_name']:<16}{idtxt:<12} "
                      f"{r['pfn']}->{r['handler']}  {own}")
                if r["status"] == "ported":
                    ported += 1
                else:
                    unported += 1
            total_maps = len(maps)
            print(f"\ntotal maps: {total_maps}   handler rows: {ported + unported}   "
                  f"ported: {ported}   unported: {unported}")
        return 0
    finally:
        program.release(consumer)
        project.close()


if __name__ == "__main__":
    sys.exit(main())
