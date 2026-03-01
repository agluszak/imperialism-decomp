#!/usr/bin/env python3
"""
Reconstruct runtime-populated Windows vtable slot mappings from code writes.

The Windows binary stores many `g_vtbl*` tables as zero-initialized data and fills
slots at runtime. This command scans code writes into vtable address ranges and
extracts `class -> slot -> function` candidates.

Outputs:
  - raw writes CSV: one row per resolved write instruction
  - best map CSV: one row per class/slot winner for downstream naming
"""

from __future__ import annotations

import argparse
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.wave_shared import is_unresolved_name


@dataclass(frozen=True)
class SlotLocation:
    class_name: str
    slot_index: int
    slot_addr: int
    source: str  # explicit_symbol | base_interval


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
        return struct.unpack_from("<I", self._data, off)[0]


def _resolve_const(vn, PcodeOp, depth: int = 0, visited: set[int] | None = None) -> int | None:
    if vn is None:
        return None
    if visited is None:
        visited = set()
    vid = id(vn)
    if vid in visited or depth > 8:
        return None
    visited.add(vid)

    if vn.isAddress() or vn.isConstant():
        return int(vn.getOffset()) & 0xFFFFFFFF

    defn = vn.getDef()
    if defn is None:
        return None

    op = defn.getOpcode()
    if op in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INDIRECT):
        return _resolve_const(defn.getInput(0), PcodeOp, depth + 1, visited)
    if op == PcodeOp.MULTIEQUAL:
        for i in range(defn.getNumInputs()):
            out = _resolve_const(defn.getInput(i), PcodeOp, depth + 1, visited)
            if out is not None:
                return out
        return None
    if op in (PcodeOp.INT_ADD, PcodeOp.PTRSUB):
        in0 = defn.getInput(0)
        in1 = defn.getInput(1)
        left = _resolve_const(in0, PcodeOp, depth + 1, visited)
        right = _resolve_const(in1, PcodeOp, depth + 1, visited)
        if left is not None and right is not None:
            return (left + right) & 0xFFFFFFFF
        return left if left is not None else right
    return None


def _parse_slot_symbol(name: str, addr_int: int, base_by_class: dict[str, int]) -> SlotLocation | None:
    # Pattern A: g_vtblTView_Slot011_...
    if name.startswith("g_vtbl") and "_Slot" in name:
        head, _sep, _rest = name.partition("_Slot")
        class_name = head.removeprefix("g_vtbl")
        base = base_by_class.get(class_name)
        if base is None:
            return None
        delta = addr_int - base
        if delta < 0 or (delta % 4) != 0:
            return None
        return SlotLocation(
            class_name=class_name,
            slot_index=delta // 4,
            slot_addr=addr_int,
            source="explicit_symbol",
        )

    # Pattern B: g_vslotTGreatPower_Slot0094_... (token is byte offset in hex)
    if name.startswith("g_vslot") and "_Slot" in name:
        head, _sep, tail = name.partition("_Slot")
        class_name = head.removeprefix("g_vslot")
        token = tail.split("_", 1)[0]
        if not token:
            return None
        try:
            byte_off = int(token, 16)
        except ValueError:
            return None
        if (byte_off % 4) != 0:
            return None
        base = base_by_class.get(class_name)
        if base is None:
            return None
        return SlotLocation(
            class_name=class_name,
            slot_index=byte_off // 4,
            slot_addr=addr_int,
            source="explicit_symbol",
        )
    return None


def _build_base_intervals(base_by_class: dict[str, int]) -> list[tuple[str, int, int]]:
    ordered = sorted((addr, cls) for cls, addr in base_by_class.items())
    out: list[tuple[str, int, int]] = []
    for idx, (addr, cls) in enumerate(ordered):
        hi = 0xFFFFFFFF if idx + 1 >= len(ordered) else ordered[idx + 1][0] - 1
        out.append((cls, addr, hi))
    return out


def _lookup_slot_location(
    to_addr: int,
    explicit_slot_by_addr: dict[int, SlotLocation],
    intervals: list[tuple[str, int, int]],
    max_slot_offset: int,
) -> SlotLocation | None:
    loc = explicit_slot_by_addr.get(to_addr)
    if loc is not None:
        return loc

    for class_name, base, hi in intervals:
        if not (base <= to_addr <= hi):
            continue
        delta = to_addr - base
        if delta < 0 or delta > max_slot_offset or (delta % 4) != 0:
            return None
        return SlotLocation(
            class_name=class_name,
            slot_index=delta // 4,
            slot_addr=to_addr,
            source="base_interval",
        )
    return None


def _extract_rows_from_executable_bytes(
    exe_mapper: PeImageMapper,
    base_by_class: dict[str, int],
    explicit_slot_by_addr: dict[int, SlotLocation],
    fm,
    af,
    text_lo: int,
    text_hi: int,
    max_slot_offset: int,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    explicit_by_class: dict[str, list[SlotLocation]] = defaultdict(list)
    for loc in explicit_slot_by_addr.values():
        explicit_by_class[loc.class_name].append(loc)
    for cls in explicit_by_class:
        explicit_by_class[cls].sort(key=lambda x: x.slot_index)

    for class_name, base_addr in sorted(base_by_class.items()):
        used_slots: set[int] = set()
        explicit_slots = explicit_by_class.get(class_name, [])

        # 1) Use explicit slot labels first (highest confidence class/slot binding).
        for loc in explicit_slots:
            ptr = exe_mapper.read_u32_va(loc.slot_addr)
            if ptr is None:
                continue
            if not (text_lo <= ptr <= text_hi):
                continue
            target_fn = fm.getFunctionAt(af.getAddress(f"{ptr:08x}"))
            if target_fn is None:
                continue
            rows.append(
                {
                    "class_name": class_name,
                    "slot_index": str(loc.slot_index),
                    "slot_addr": f"0x{loc.slot_addr:08x}",
                    "vtable_base_addr": f"0x{base_addr:08x}",
                    "source": "file_bytes_explicit",
                    "writer_addr": "",
                    "writer_name": "",
                    "ins_addr": "",
                    "target_addr": f"0x{ptr:08x}",
                    "target_name": str(target_fn.getName()),
                    "target_generic": "1" if is_unresolved_name(str(target_fn.getName())) else "0",
                }
            )
            used_slots.add(loc.slot_index)

        # 2) Fill additional contiguous slots from base for unlabeled ranges.
        valid_seen = 0
        invalid_streak = 0
        for off in range(0, max_slot_offset + 4, 4):
            slot_idx = off // 4
            if slot_idx in used_slots:
                continue
            slot_addr = (base_addr + off) & 0xFFFFFFFF
            ptr = exe_mapper.read_u32_va(slot_addr)
            if ptr is None:
                if valid_seen > 0:
                    invalid_streak += 1
                    if invalid_streak >= 3:
                        break
                continue
            if text_lo <= ptr <= text_hi:
                target_fn = fm.getFunctionAt(af.getAddress(f"{ptr:08x}"))
                if target_fn is not None:
                    rows.append(
                        {
                            "class_name": class_name,
                            "slot_index": str(slot_idx),
                            "slot_addr": f"0x{slot_addr:08x}",
                            "vtable_base_addr": f"0x{base_addr:08x}",
                            "source": "file_bytes_base",
                            "writer_addr": "",
                            "writer_name": "",
                            "ins_addr": "",
                            "target_addr": f"0x{ptr:08x}",
                            "target_name": str(target_fn.getName()),
                            "target_generic": (
                                "1" if is_unresolved_name(str(target_fn.getName())) else "0"
                            ),
                        }
                    )
                    used_slots.add(slot_idx)
                    valid_seen += 1
                    invalid_streak = 0
                    continue
            if valid_seen > 0:
                invalid_streak += 1
                if invalid_streak >= 3:
                    break

    return rows


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract runtime vtable slot writes into class/slot/function mapping CSVs.",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/windows_runtime_vtable_slot_writes.csv",
        help="Raw write evidence output CSV.",
    )
    ap.add_argument(
        "--out-best-csv",
        default="tmp_decomp/windows_runtime_vtable_slot_map.csv",
        help="Best class/slot map output CSV.",
    )
    ap.add_argument(
        "--classes",
        default="",
        help="Optional comma-separated class filter.",
    )
    ap.add_argument(
        "--max-slot-offset",
        type=lambda s: int(str(s), 0),
        default=0x400,
        help="Max byte offset from g_vtbl<Class> for base-interval inference (default: 0x400).",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_best_csv = Path(args.out_best_csv)
    if not out_best_csv.is_absolute():
        out_best_csv = root / out_best_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_best_csv.parent.mkdir(parents=True, exist_ok=True)

    class_filter = {x.strip() for x in args.classes.split(",") if x.strip()}

    raw_rows: list[dict[str, str]] = []

    with open_program(root) as program:
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        rm = program.getReferenceManager()
        listing = program.getListing()
        mem = program.getMemory()
        af = program.getAddressFactory().getDefaultAddressSpace()

        from ghidra.program.model.pcode import PcodeOp  # noqa: PLC0415

        base_by_class: dict[str, int] = {}
        explicit_slot_by_addr: dict[int, SlotLocation] = {}

        sym_it = st.getAllSymbols(True)
        while sym_it.hasNext():
            sym = sym_it.next()
            sym_name = str(sym.getName())
            sym_addr = sym.getAddress()
            if sym_addr is None:
                continue
            if str(sym_addr).startswith("EXTERNAL:"):
                continue
            addr_int = sym_addr.getOffset() & 0xFFFFFFFF

            if sym_name.startswith("g_vtbl") and "_Slot" not in sym_name:
                class_name = sym_name.removeprefix("g_vtbl")
                if class_name:
                    base_by_class[class_name] = addr_int

        sym_it = st.getAllSymbols(True)
        while sym_it.hasNext():
            sym = sym_it.next()
            sym_name = str(sym.getName())
            sym_addr = sym.getAddress()
            if sym_addr is None:
                continue
            if str(sym_addr).startswith("EXTERNAL:"):
                continue
            addr_int = sym_addr.getOffset() & 0xFFFFFFFF
            loc = _parse_slot_symbol(sym_name, addr_int, base_by_class)
            if loc is not None:
                explicit_slot_by_addr[addr_int] = loc

        if class_filter:
            base_by_class = {k: v for k, v in base_by_class.items() if k in class_filter}
            explicit_slot_by_addr = {
                k: v for k, v in explicit_slot_by_addr.items() if v.class_name in class_filter
            }

        intervals = _build_base_intervals(base_by_class)

        fit = fm.getFunctions(True)
        while fit.hasNext():
            writer_fn = fit.next()
            writer_name = str(writer_fn.getName())
            ins_it = listing.getInstructions(writer_fn.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                refs_from = ins.getReferencesFrom()
                if refs_from is None or len(refs_from) == 0:
                    continue

                write_targets: list[int] = []
                for ref in refs_from:
                    rtype = ref.getReferenceType()
                    if rtype is None or not rtype.isWrite():
                        continue
                    to_addr = ref.getToAddress()
                    if to_addr is None or str(to_addr).startswith("EXTERNAL:"):
                        continue
                    write_targets.append(to_addr.getOffset() & 0xFFFFFFFF)
                if not write_targets:
                    continue

                stores = [op for op in ins.getPcode() if op.getOpcode() == PcodeOp.STORE]
                if not stores:
                    continue

                for target_addr in write_targets:
                    loc = _lookup_slot_location(
                        target_addr,
                        explicit_slot_by_addr,
                        intervals,
                        args.max_slot_offset,
                    )
                    if loc is None:
                        continue

                    fn_target_addr: int | None = None
                    for op in stores:
                        if op.getNumInputs() < 3:
                            continue
                        store_addr = _resolve_const(op.getInput(1), PcodeOp)
                        if store_addr is None:
                            continue
                        if (store_addr & 0xFFFFFFFF) != target_addr:
                            continue
                        maybe_val = _resolve_const(op.getInput(2), PcodeOp)
                        if maybe_val is None:
                            continue
                        maybe_fn = fm.getFunctionAt(
                            program.getAddressFactory()
                            .getDefaultAddressSpace()
                            .getAddress(f"{maybe_val & 0xFFFFFFFF:08x}")
                        )
                        if maybe_fn is None:
                            continue
                        fn_target_addr = maybe_val & 0xFFFFFFFF
                        break

                    if fn_target_addr is None:
                        continue

                    target_fn = fm.getFunctionAt(
                        program.getAddressFactory()
                        .getDefaultAddressSpace()
                        .getAddress(f"{fn_target_addr:08x}")
                    )
                    if target_fn is None:
                        continue

                    raw_rows.append(
                        {
                            "class_name": loc.class_name,
                            "slot_index": str(loc.slot_index),
                            "slot_addr": f"0x{loc.slot_addr:08x}",
                            "vtable_base_addr": f"0x{(loc.slot_addr - (loc.slot_index * 4)) & 0xFFFFFFFF:08x}",
                            "source": loc.source,
                            "writer_addr": f"0x{writer_fn.getEntryPoint().getOffset() & 0xFFFFFFFF:08x}",
                            "writer_name": writer_name,
                            "ins_addr": f"0x{ins.getAddress().getOffset() & 0xFFFFFFFF:08x}",
                            "target_addr": f"0x{fn_target_addr:08x}",
                            "target_name": str(target_fn.getName()),
                            "target_generic": "1" if is_unresolved_name(str(target_fn.getName())) else "0",
                        }
                    )

        # File-bytes fallback: required when Ghidra in-project memory bytes are zeroed.
        exe_path = Path(program.getExecutablePath())
        if exe_path.exists():
            try:
                text_blk = mem.getBlock(".text")
                text_lo = text_blk.getStart().getOffset() & 0xFFFFFFFF
                text_hi = text_blk.getEnd().getOffset() & 0xFFFFFFFF
                exe_mapper = PeImageMapper.from_executable(exe_path)
                file_rows = _extract_rows_from_executable_bytes(
                    exe_mapper=exe_mapper,
                    base_by_class=base_by_class,
                    explicit_slot_by_addr=explicit_slot_by_addr,
                    fm=fm,
                    af=af,
                    text_lo=text_lo,
                    text_hi=text_hi,
                    max_slot_offset=args.max_slot_offset,
                )
                raw_rows.extend(file_rows)
                print(
                    f"[file-bytes] exe={exe_path} added_rows={len(file_rows)} "
                    f"classes={len({r['class_name'] for r in file_rows})}"
                )
            except Exception as ex:
                print(f"[warn] file-bytes extraction failed: {ex}")
        else:
            print(f"[warn] executable path missing on disk: {exe_path}")

    write_csv_rows(
        out_csv,
        raw_rows,
        [
            "class_name",
            "slot_index",
            "slot_addr",
            "vtable_base_addr",
            "source",
            "writer_addr",
            "writer_name",
            "ins_addr",
            "target_addr",
            "target_name",
            "target_generic",
        ],
    )

    # Aggregate best mapping per class+slot.
    per_slot_target_counts: dict[tuple[str, int], Counter[str]] = defaultdict(Counter)
    target_name_by_addr: dict[str, str] = {}
    sources_by_slot: dict[tuple[str, int], set[str]] = defaultdict(set)
    writers_by_slot_target: dict[tuple[str, int, str], set[str]] = defaultdict(set)
    vtable_base_by_slot: dict[tuple[str, int], str] = {}

    for row in raw_rows:
        cls = row["class_name"]
        slot = int(row["slot_index"])
        target_addr = row["target_addr"]
        writer_addr = row["writer_addr"]
        per_slot_target_counts[(cls, slot)][target_addr] += 1
        target_name_by_addr[target_addr] = row["target_name"]
        sources_by_slot[(cls, slot)].add(row["source"])
        writers_by_slot_target[(cls, slot, target_addr)].add(writer_addr)
        vbase = (row.get("vtable_base_addr") or "").strip()
        if vbase:
            vtable_base_by_slot[(cls, slot)] = vbase

    best_rows: list[dict[str, str]] = []
    for (cls, slot), counter in sorted(per_slot_target_counts.items(), key=lambda x: (x[0][0], x[0][1])):
        ranked = sorted(
            counter.items(),
            key=lambda kv: (
                -kv[1],
                1 if is_unresolved_name(target_name_by_addr.get(kv[0], "")) else 0,
                kv[0],
            ),
        )
        winner_addr, winner_count = ranked[0]
        second_count = ranked[1][1] if len(ranked) > 1 else 0
        candidate_count = len(ranked)
        total_writes = sum(counter.values())
        unique_writers = len(writers_by_slot_target[(cls, slot, winner_addr)])
        if candidate_count == 1:
            confidence = "high"
        elif winner_count >= 2 and winner_count > second_count:
            confidence = "medium"
        else:
            confidence = "low"
        best_rows.append(
            {
                "class_name": cls,
                "slot_index": str(slot),
                "vtable_base_addr": vtable_base_by_slot.get((cls, slot), ""),
                "target_addr": winner_addr,
                "target_name": target_name_by_addr.get(winner_addr, ""),
                "confidence": confidence,
                "winner_writes": str(winner_count),
                "total_writes": str(total_writes),
                "candidate_count": str(candidate_count),
                "unique_writers": str(unique_writers),
                "slot_source": ";".join(sorted(sources_by_slot[(cls, slot)])),
            }
        )

    write_csv_rows(
        out_best_csv,
        best_rows,
        [
            "class_name",
            "slot_index",
            "vtable_base_addr",
            "target_addr",
            "target_name",
            "confidence",
            "winner_writes",
            "total_writes",
            "candidate_count",
            "unique_writers",
            "slot_source",
        ],
    )

    print(
        f"[saved] {out_csv} rows={len(raw_rows)} "
        f"class_slots={len(per_slot_target_counts)}"
    )
    print(f"[saved] {out_best_csv} rows={len(best_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
