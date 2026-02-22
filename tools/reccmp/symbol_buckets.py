#!/usr/bin/env python3
"""Shared symbol classification helpers for reccmp workflows."""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path


BUCKET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "mfc_likely",
        re.compile(
            r"^(Afx|afx)|"
            r"(Mfc|MFC)|"
            r"^(CWnd|CDC|CDocument|CFileException|CListCtrl|CStatusBarCtrl|CToolBarCtrl|CTreeCtrl|CObArray)::|"
            r"^C[A-Z][A-Za-z0-9_]*::",
            re.IGNORECASE,
        ),
    ),
    (
        "crt_likely",
        re.compile(
            r"(CRT|Crt|WinMainCRTStartup|_WinMainCRTStartup|"
            r"StructuredException|ExceptionDispatch|Tls|Heap|"
            r"malloc|free|new|delete|qsort|bsearch|"
            r"memcpy|memset|memcmp|strlen|strcpy|strcmp)",
            re.IGNORECASE,
        ),
    ),
    (
        "directx_audio_net_likely",
        re.compile(
            r"(DirectSound|DPlay|WINMM|mmio|mci|Sound|Wave|Midi|Joystick|auxGet|timeGetTime)",
            re.IGNORECASE,
        ),
    ),
    (
        "game_tclass",
        re.compile(r"^T[A-Z][A-Za-z0-9_]*::"),
    ),
    (
        "thunk",
        re.compile(r"^thunk_"),
    ),
]


@dataclass(frozen=True)
class FunctionSymbol:
    address: int
    name: str
    size: int | None


def classify_name(name: str) -> str:
    for bucket, rx in BUCKET_PATTERNS:
        if rx.search(name):
            return bucket
    return "game_or_unknown"


def parse_function_symbols(path: Path) -> list[FunctionSymbol]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing symbols CSV: {path}")
    out: list[FunctionSymbol] = []
    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        for row in reader:
            if (row.get("type") or "").strip().lower() != "function":
                continue
            addr_text = (row.get("address") or "").strip()
            name = (row.get("name") or "").strip()
            size_text = (row.get("size") or "").strip()
            if not addr_text or not name:
                continue
            try:
                addr = int(addr_text, 16)
            except ValueError:
                continue
            size = None
            if size_text:
                try:
                    size = int(size_text, 10)
                except ValueError:
                    pass
            out.append(FunctionSymbol(address=addr, name=name, size=size))
    return out


def parse_reccmp_report(path: Path) -> dict[int, float]:
    """Return map of original address -> similarity percent."""
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: dict[int, float] = {}
    for row in raw.get("data", []):
        addr_text = str(row.get("address", "")).strip().lower()
        if addr_text.startswith("0x"):
            addr_text = addr_text[2:]
        if not addr_text:
            continue
        try:
            addr = int(addr_text, 16)
            out[addr] = float(row.get("matching", 0.0)) * 100.0
        except ValueError:
            continue
    return out

