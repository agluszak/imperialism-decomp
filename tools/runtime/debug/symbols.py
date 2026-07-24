"""Symbolize runtime-test addresses from the VC5 linker map."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess

from reccmp.cvdump.demangler import msvc_demangle


PUBLIC_RE = re.compile(
    r"^\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{8})"
    r"(?:\s+\w)?\s+(.+)$"
)
FRAME_RE = re.compile(r"^#(\d+)\s+(0x[0-9A-Fa-f]+)")


@dataclass(frozen=True)
class MapSymbol:
    address: int
    decorated_name: str
    object_name: str


class LinkerMap:
    def __init__(self, symbols: list[MapSymbol]) -> None:
        self.symbols = sorted(symbols, key=lambda symbol: symbol.address)
        self.addresses = [symbol.address for symbol in self.symbols]

    @classmethod
    def read(cls, path: Path) -> "LinkerMap":
        symbols: list[MapSymbol] = []
        for line in path.read_text(encoding="latin-1").splitlines():
            match = PUBLIC_RE.match(line)
            if match:
                symbols.append(
                    MapSymbol(int(match.group(2), 16), match.group(1), match.group(3))
                )
        return cls(symbols)

    def lookup(self, address: int) -> MapSymbol | None:
        if not self.addresses or address < self.addresses[0] or address > self.addresses[-1] + 0x10000:
            return None
        index = bisect_right(self.addresses, address) - 1
        return self.symbols[index] if index >= 0 else None

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
    frames: list[tuple[int, int, MapSymbol]] = []
    for line in report_path.read_text(encoding="utf-8").splitlines():
        match = FRAME_RE.match(line)
        if not match:
            continue
        address = int(match.group(2), 16)
        symbol = linker_map.lookup(address)
        if symbol is not None:
            frames.append((int(match.group(1)), address, symbol))
    names = list(dict.fromkeys(symbol.decorated_name for _, _, symbol in frames))
    demangled = _demangle(names)
    output_path = report_path.with_name(
        report_path.name.replace("debugger-stop-", "symbolized-stack-")
    )
    with output_path.open("w", encoding="utf-8") as output:
        for frame, address, symbol in frames:
            name = demangled.get(symbol.decorated_name, symbol.decorated_name)
            output.write(
                f"#{frame} 0x{address:08x} {name}+0x{address - symbol.address:x} "
                f"[{symbol.object_name}]\n"
            )
    return output_path
