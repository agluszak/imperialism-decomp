from __future__ import annotations

import re
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.ghidra_session import open_program

_ECX_OFFSET_RE = re.compile(r"\[ECX(?:\s*([+-])\s*(0x[0-9A-Fa-f]+|\d+))?\]")


@dataclass(frozen=True)
class PeSection:
    va_start: int
    va_end: int
    file_off: int
    raw_size: int


class PeImageMapper:
    def __init__(self, exe_path: Path, image_base: int, sections: list[PeSection]) -> None:
        self.exe_path = exe_path
        self.image_base = image_base
        self.sections = sections
        self._data = exe_path.read_bytes()

    @classmethod
    def from_executable(cls, exe_path: Path) -> "PeImageMapper":
        data = exe_path.read_bytes()
        if len(data) < 0x100:
            raise ValueError(f"PE too small: {exe_path}")

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError(f"not a PE image: {exe_path}")

        number_of_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        size_of_optional_header = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        opt_off = e_lfanew + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        if magic == 0x10B:  # PE32
            image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
        elif magic == 0x20B:  # PE32+
            image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        else:
            raise ValueError(f"unsupported PE optional header magic: 0x{magic:04x}")

        sec_off = opt_off + size_of_optional_header
        sections: list[PeSection] = []
        for idx in range(number_of_sections):
            base = sec_off + idx * 40
            virtual_size = struct.unpack_from("<I", data, base + 8)[0]
            virtual_address = struct.unpack_from("<I", data, base + 12)[0]
            size_of_raw_data = struct.unpack_from("<I", data, base + 16)[0]
            ptr_to_raw = struct.unpack_from("<I", data, base + 20)[0]
            va_start = (image_base + virtual_address) & 0xFFFFFFFF
            span = max(virtual_size, size_of_raw_data)
            va_end = (va_start + span - 1) & 0xFFFFFFFF if span > 0 else va_start
            sections.append(
                PeSection(
                    va_start=va_start,
                    va_end=va_end,
                    file_off=ptr_to_raw,
                    raw_size=size_of_raw_data,
                )
            )
        return cls(exe_path=exe_path, image_base=image_base, sections=sections)

    def va_to_file_off(self, va: int) -> int | None:
        for sec in self.sections:
            if sec.va_start <= va <= sec.va_end:
                delta = va - sec.va_start
                if delta < 0 or delta + 4 > sec.raw_size:
                    return None
                off = sec.file_off + delta
                if off < 0 or off + 4 > len(self._data):
                    return None
                return off
        return None

    def read_u32_va(self, va: int) -> int | None:
        off = self.va_to_file_off(va)
        if off is None:
            return None
        return struct.unpack_from("<I", self._data, off)[0] & 0xFFFFFFFF


def _read_u32_le_mem(mem, addr_obj) -> int | None:
    try:
        buf = bytearray(4)
        cnt = mem.getBytes(addr_obj, buf)
        if cnt < 4:
            return None
        return int.from_bytes(buf, "little") & 0xFFFFFFFF
    except Exception:
        return None


def _find_block(program, name: str):
    mem = program.getMemory()
    blk = mem.getBlock(name)
    if blk is not None:
        return blk
    it = mem.getBlocks()
    want = name.lower()
    while it.hasNext():
        b = it.next()
        if str(b.getName()).lower() == want:
            return b
    return None


def _parse_ecx_offset(ins_text: str) -> int:
    m = _ECX_OFFSET_RE.search(ins_text)
    if not m:
        return 0
    sign = m.group(1)
    token = m.group(2)
    if not token:
        return 0
    try:
        val = int(token, 0)
    except ValueError:
        val = int(token, 16)
    if sign == "-":
        val = -val
    return val


def run(
    project_root: Path,
    *,
    out_csv: Path,
    min_run: int = 2,
    max_gap: int = 0,
) -> dict[str, int]:
    with open_program(project_root) as program:
        mem = program.getMemory()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()
        st = program.getSymbolTable()
        af = program.getAddressFactory().getDefaultAddressSpace()

        text_block = _find_block(program, ".text")
        rdata_block = _find_block(program, ".rdata")
        if text_block is None:
            raise RuntimeError("missing .text memory block")
        if rdata_block is None:
            raise RuntimeError("missing .rdata memory block")

        text_lo = int(text_block.getStart().getOffset()) & 0xFFFFFFFF
        text_hi = int(text_block.getEnd().getOffset()) & 0xFFFFFFFF
        rdata_lo = int(rdata_block.getStart().getOffset()) & 0xFFFFFFFF
        rdata_hi = int(rdata_block.getEnd().getOffset()) & 0xFFFFFFFF

        pe_mapper = None
        source_label = "program_memory"
        exe_path = Path(program.getExecutablePath())
        if exe_path.exists():
            try:
                pe_mapper = PeImageMapper.from_executable(exe_path)
                source_label = "file_bytes"
            except Exception as ex:
                print(f"[warn] scan_windows_static_vtables: PE mapper failed, fallback to memory: {ex}")
        else:
            print(f"[warn] scan_windows_static_vtables: executable path missing: {exe_path}")

        def read_u32(va: int) -> int | None:
            if pe_mapper is not None:
                val = pe_mapper.read_u32_va(va)
                if val is not None:
                    return val
            return _read_u32_le_mem(mem, af.getAddress(f"{va:08x}"))

        def ptr_to_fn(ptr: int):
            if ptr < text_lo or ptr > text_hi:
                return None
            try:
                addr_obj = af.getAddress(f"{ptr:08x}")
            except Exception:
                return None
            fn = fm.getFunctionAt(addr_obj)
            if fn is not None:
                return fn
            return fm.getFunctionContaining(addr_obj)

        runs: list[tuple[int, list[tuple[int, int | None, object | None]]]] = []
        cur = rdata_lo
        max_addr = rdata_hi - 3
        while cur <= max_addr:
            start = cur
            slots: list[tuple[int, int | None, object | None]] = []
            valid_count = 0
            gap_count = 0

            while cur <= max_addr:
                ptr = read_u32(cur)
                fn = None if ptr is None else ptr_to_fn(ptr)
                if fn is not None:
                    slots.append((len(slots), ptr, fn))
                    valid_count += 1
                    gap_count = 0
                    cur += 4
                    continue
                if valid_count == 0:
                    cur += 4
                    break
                if gap_count < max_gap:
                    slots.append((len(slots), None, None))
                    gap_count += 1
                    cur += 4
                    continue
                break

            if valid_count >= min_run:
                while slots and slots[-1][1] is None:
                    slots.pop()
                if slots:
                    runs.append((start, slots))

            if cur == start:
                cur += 4

        out_rows: list[dict[str, str]] = []
        for start, slots in runs:
            start_obj = af.getAddress(f"{start:08x}")
            refs = rm.getReferencesTo(start_obj)
            class_hits: Counter[str] = Counter()
            ecx_offsets: Counter[int] = Counter()
            ref_total = 0
            for ref in refs:
                ref_total += 1
                from_addr = ref.getFromAddress()
                from_fn = fm.getFunctionContaining(from_addr)
                if from_fn is not None:
                    ns = from_fn.getParentNamespace()
                    if ns is not None:
                        ns_name = str(ns.getName())
                        if ns_name.lower() != "global":
                            class_hits[ns_name] += 1
                ins = listing.getInstructionAt(from_addr)
                if ins is not None:
                    ecx_offsets[_parse_ecx_offset(str(ins))] += 1

            class_name = ""
            if class_hits:
                class_name = class_hits.most_common(1)[0][0]
            else:
                sym = st.getPrimarySymbol(start_obj)
                if sym is not None:
                    sym_name = str(sym.getName())
                    if sym_name.startswith("g_vtbl") and "_Slot" not in sym_name:
                        class_name = sym_name.removeprefix("g_vtbl")

            ctor_off = 0
            if ecx_offsets:
                ctor_off = ecx_offsets.most_common(1)[0][0]

            if not class_name:
                confidence = "low"
            elif len(class_hits) == 1:
                confidence = "high"
            else:
                confidence = "medium"

            evidence_parts = [f"refs={ref_total}", f"scan_source={source_label}"]
            if class_hits:
                evidence_parts.append(
                    "class_hits="
                    + "|".join(
                        f"{k}:{v}" for k, v in sorted(class_hits.items(), key=lambda kv: (-kv[1], kv[0]))[:4]
                    )
                )
            evidence_parts.append(f"valid_slots={sum(1 for _i, ptr, _fn in slots if ptr is not None)}")
            evidence = ";".join(evidence_parts)

            for slot_idx, ptr, fn in slots:
                if ptr is None or fn is None:
                    continue
                out_rows.append(
                    {
                        "vtable_addr": f"0x{start:08x}",
                        "slot_idx": str(slot_idx),
                        "target_func_addr": f"0x{ptr:08x}",
                        "target_func_name": str(fn.getName()),
                        "class_name": class_name,
                        "constructor_offset": str(ctor_off),
                        "confidence": confidence,
                        "evidence": evidence,
                    }
                )

    out_rows.sort(key=lambda r: (r["vtable_addr"], int(r["slot_idx"])))
    write_csv_rows(
        out_csv,
        out_rows,
        [
            "vtable_addr",
            "slot_idx",
            "target_func_addr",
            "target_func_name",
            "class_name",
            "constructor_offset",
            "confidence",
            "evidence",
        ],
    )
    print(
        f"[scan_windows_static_vtables] rows={len(out_rows)} vtables={len({r['vtable_addr'] for r in out_rows})} "
        f"source={source_label} -> {out_csv}"
    )
    return {
        "rows": len(out_rows),
        "vtable_count": len({r["vtable_addr"] for r in out_rows}),
        "source_file_bytes": 1 if source_label == "file_bytes" else 0,
    }

