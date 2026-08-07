"""Symbolize runtime-test addresses from the VC5 linker map."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess

from reccmp.cvdump.demangler import msvc_demangle


PUBLIC_RE = re.compile(
    r"^\s+([0-9A-Fa-f]+):([0-9A-Fa-f]+)\s+(\S+)\s+([0-9A-Fa-f]{8})"
    r"(?:\s+(\w))?\s+(.+)$"
)
FRAME_RE = re.compile(r"^#(\d+)\s+(0x[0-9A-Fa-f]+)")
MAX_UNBOUNDED_FUNCTION_BYTES = 0x1000


@dataclass(frozen=True)
class MapSymbol:
    section: int
    offset: int
    address: int
    decorated_name: str
    object_name: str
    is_function: bool


@dataclass(frozen=True)
class SymbolResolution:
    address: int
    symbol: MapSymbol | None
    confidence: str
    reason: str


class LinkerMap:
    def __init__(self, symbols: list[MapSymbol]) -> None:
        self.symbols = sorted(symbols, key=lambda symbol: symbol.address)
        self.addresses = [symbol.address for symbol in self.symbols]
        self.section_bases: dict[int, int] = {}
        for symbol in self.symbols:
            self.section_bases.setdefault(symbol.section, symbol.address - symbol.offset)

    @classmethod
    def read(cls, path: Path) -> "LinkerMap":
        symbols: list[MapSymbol] = []
        for line in path.read_text(encoding="latin-1").splitlines():
            match = PUBLIC_RE.match(line)
            if match:
                symbols.append(
                    MapSymbol(
                        section=int(match.group(1), 16),
                        offset=int(match.group(2), 16),
                        decorated_name=match.group(3),
                        address=int(match.group(4), 16),
                        is_function=match.group(5) == "f",
                        object_name=match.group(6),
                    )
                )
        return cls(symbols)

    def lookup(self, address: int) -> MapSymbol | None:
        resolution = self.resolve(address)
        return resolution.symbol if resolution.confidence == "high" else None

    def resolve(self, address: int) -> SymbolResolution:
        if not self.addresses or address < self.addresses[0]:
            return SymbolResolution(address, None, "unresolved", "before first public symbol")
        index = bisect_right(self.addresses, address) - 1
        symbol = self.symbols[index]
        if not symbol.is_function:
            return SymbolResolution(address, None, "unresolved", "nearest public is data")
        section_base = self.section_bases[symbol.section]
        if address < section_base:
            return SymbolResolution(address, None, "unresolved", "address precedes section")
        next_symbol = self.symbols[index + 1] if index + 1 < len(self.symbols) else None
        if next_symbol is not None:
            if next_symbol.section != symbol.section:
                next_base = self.section_bases[next_symbol.section]
                if address >= next_base:
                    return SymbolResolution(address, None, "unresolved", "address crosses section")
            elif address >= next_symbol.address:
                return SymbolResolution(address, None, "unresolved", "address crosses symbol extent")
        displacement = address - symbol.address
        if next_symbol is None or next_symbol.section != symbol.section:
            if displacement >= MAX_UNBOUNDED_FUNCTION_BYTES:
                return SymbolResolution(
                    address,
                    None,
                    "low",
                    f"unbounded function displacement 0x{displacement:x}",
                )
        return SymbolResolution(address, symbol, "high", "within function extent")

    def find_decorated(self, decorated_name: str) -> MapSymbol | None:
        for symbol in self.symbols:
            if symbol.decorated_name == decorated_name:
                return symbol
        return None


def _demangle(names: list[str]) -> dict[str, str]:
    if not names:
        return {}
    try:
        completed = subprocess.run(
            ["llvm-undname"],
            input="\n".join(names) + "\n",
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return {
            name: demangled
            for name in names
            if (demangled := msvc_demangle(name)) is not None
        }
    lines = completed.stdout.splitlines()
    demangled: dict[str, str] = {}
    cursor = 0
    for name in names:
        while cursor < len(lines) and lines[cursor] != name:
            cursor += 1
        if cursor + 1 < len(lines):
            demangled[name] = lines[cursor + 1]
            cursor += 2
    for name in names:
        if name not in demangled:
            fallback = msvc_demangle(name)
            if fallback is not None:
                demangled[name] = fallback
    return demangled


def symbolize_gdb_report(report_path: Path, map_path: Path) -> Path | None:
    if not map_path.is_file():
        return None
    linker_map = LinkerMap.read(map_path)
    frames: list[tuple[int, SymbolResolution]] = []
    for line in report_path.read_text(encoding="utf-8").splitlines():
        match = FRAME_RE.match(line)
        if not match:
            continue
        address = int(match.group(2), 16)
        frames.append((int(match.group(1)), linker_map.resolve(address)))
    names = list(
        dict.fromkeys(
            resolution.symbol.decorated_name
            for _, resolution in frames
            if resolution.symbol is not None
        )
    )
    demangled = _demangle(names)
    output_path = report_path.with_name(
        report_path.name.replace("debugger-stop-", "symbolized-stack-")
    )
    with output_path.open("w", encoding="utf-8") as output:
        for frame, resolution in frames:
            address = resolution.address
            symbol = resolution.symbol
            if symbol is None:
                output.write(
                    f"#{frame} 0x{address:08x} <unresolved:{resolution.confidence}> "
                    f"{resolution.reason}\n"
                )
                continue
            name = demangled.get(symbol.decorated_name, symbol.decorated_name)
            output.write(
                f"#{frame} 0x{address:08x} {name}+0x{address - symbol.address:x} "
                f"[{symbol.object_name}]\n"
            )
    return output_path
