#!/usr/bin/env python3
"""Shared symbol classification helpers for reccmp workflows."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.report_score import effective_matching


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
        "wrapper_likely",
        re.compile(
            r"(WrapperFor_|Wrapper_|PassThrough|Passthrough|ForwardTo|Forwarder|Trampoline)",
            re.IGNORECASE,
        ),
    ),
    (
        "thunk",
        re.compile(r"(^|::)thunk_", re.IGNORECASE),
    ),
    (
        "game_tclass",
        re.compile(r"^T[A-Z][A-Za-z0-9_]*::"),
    ),
]


@dataclass(frozen=True)
class FunctionSymbol:
    address: int
    name: str
    size: int | None


# Provenance values in config/original_entities.csv that assert a library
# identity established by the MSVC500 object-matcher oracle (byte evidence),
# as opposed to a name-shape guess.
LIBRARY_ORACLE_PROVENANCES = frozenset({
    "msvc500_library_oracle",
    "msvc500_library_override",
})


def load_library_evidence(
    repo_root: Path,
    reviewed_csv: Path | None = None,
    symbols_csv: Path | None = None,
    allowlist_csv: Path | None = None,
) -> dict[int, str]:
    """Address -> evidence label for every function with LIBRARY evidence.

    Evidence means byte/provenance proof, never name shape (Hard Rule 6):
    - a row in config/reviewed_library_identities.csv (agent-reviewed identity,
      projected to `// LIBRARY:`/`// SYNTHETIC:` markers by stubgen);
    - an original_entities.csv row whose provenance is one of
      LIBRARY_ORACLE_PROVENANCES (MSVC500 object-matcher byte evidence);
    - minus config/library_oracle_gamecode_allowlist.csv (oracle false
      positives confirmed to be game code).
    """
    from tools.mfc.reviewed_identities import DEFAULT_REVIEWED, load_reviewed_identities

    reviewed_csv = reviewed_csv or repo_root / DEFAULT_REVIEWED
    symbols_csv = symbols_csv or repo_root / "config" / "original_entities.csv"
    allowlist_csv = allowlist_csv or repo_root / "config" / "library_oracle_gamecode_allowlist.csv"

    evidence: dict[int, str] = {}
    for row in read_pipe_rows(symbols_csv):
        provenance = (row.get("provenance") or "").strip()
        if provenance not in LIBRARY_ORACLE_PROVENANCES:
            continue
        try:
            evidence[int((row.get("address") or "").strip(), 16)] = f"oracle:{provenance}"
        except ValueError:
            continue

    for identity in load_reviewed_identities(reviewed_csv):
        label = identity.library_family or identity.kind.lower()
        evidence[identity.address] = f"reviewed:{label}"

    if allowlist_csv.is_file():
        for row in read_pipe_rows(allowlist_csv):
            addr_text = (row.get("address") or "").strip()
            try:
                evidence.pop(int(addr_text, 16), None)
            except ValueError:
                continue

    return evidence


def classify_name(name: str) -> str:
    for bucket, rx in BUCKET_PATTERNS:
        if rx.search(name):
            return bucket
    return "game_or_unknown"


def parse_function_symbols(path: Path) -> list[FunctionSymbol]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing symbols CSV: {path}")
    out: list[FunctionSymbol] = []
    for row in read_pipe_rows(path):
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
            out[addr] = effective_matching(row) * 100.0
        except ValueError:
            continue
    return out
