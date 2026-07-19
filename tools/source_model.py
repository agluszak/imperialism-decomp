#!/usr/bin/env python3
"""The central source model: one scan, one parse, one authority.

Everything the pipeline knows about the source model is built here, once:

  - **marker claims** — every `// FUNCTION/STUB/TEMPLATE/SYNTHETIC/LIBRARY:`
    marker in `src/` + `include/`, with the qualified name and prototype parsed
    from the C++ declaration that follows (FUNCTION) or the convention comment
    line under the marker (SYNTHETIC/TEMPLATE/LIBRARY). Free-function names are
    first-class — a parsed name does not need `::`.
  - **vtables** — every `// VTABLE:` annotation with its owning class (parsed
    from the following `class`/`struct` declaration).
  - **globals** — every `// GLOBAL:` annotation with its declared name.
  - **reviewed library identities** — `config/reviewed_library_identities.csv`
    rows become LIBRARY claims (origin "reviewed"); a source marker at the same
    address wins.

Downstream consumers (generate_symbols, stubgen, apply_source, func_status,
gates) import from this module — none of them scan annotations independently.
`build_model()` is cheap (<1s) and pure; `write_model()` also emits
`<gen-dir>/source_model.json` for external tooling.

Duplicate function-kind claims are a hard error (one address, one owner).
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from tools.common.file_scan import iter_files, is_generated_source_path
from tools.common.markers import function_marker_regex
from tools.common.repo import repo_root_from_file, resolve_repo_path

DEFAULT_GEN_DIR = "build-msvc500/generated"
MODEL_NAME = "source_model.json"
REVIEWED_CSV = "config/reviewed_library_identities.csv"

_KINDS = ("FUNCTION", "STUB", "TEMPLATE", "SYNTHETIC", "LIBRARY")
_VTABLE_RE = re.compile(r"//\s*VTABLE\s*:\s*(\w+)\s+(?:0x)?([0-9a-fA-F]+)", re.IGNORECASE)
_GLOBAL_RE = re.compile(
    r"//\s*GLOBAL\s*:\s*(\w+)\s+(?:0x)?([0-9a-fA-F]+)(?:\s+(\S+))?", re.IGNORECASE
)
_CLASS_DECL_RE = re.compile(r"^\s*(?:class|struct)\s+([A-Za-z_]\w*)")
# Declaration head: `Ret [Class::]Name(args`. Qualified or free.
_DEF_RE = re.compile(
    r"^[\w:<>*&~\s]*?\b((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*\("
)
_NAME_COMMENT_RE = re.compile(r"^//\s*((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*$")
# Linker-symbol spellings: MSVC C++ mangles start with '?', C symbols carry the
# cdecl underscore on top of any source underscores (`___ld12tod` = __ld12tod).
_MANGLED_COMMENT_RE = re.compile(r"^//\s*(\?\S+|\S*@\S*|___\S+)\s*$")
# Names that are C++ keywords/control flow can never be function names.
_NOT_NAMES = frozenset(
    "if while for switch return sizeof new delete else do catch throw".split()
)


@dataclass(frozen=True)
class Claim:
    address: int
    kind: str  # FUNCTION/STUB/TEMPLATE/SYNTHETIC/LIBRARY
    file: str  # repo-relative posix path ("" for reviewed rows)
    line: int  # 1-based marker line (0 for reviewed rows)
    name: str = ""  # source-derived qualified/free name ("" if unparsable)
    prototype: str = ""  # source declaration head ("" if unparsable)
    symbol: str = ""  # mangled linker symbol when known
    origin: str = "marker"  # marker | reviewed


@dataclass
class SourceModel:
    target: str
    functions: dict[int, Claim] = field(default_factory=dict)
    vtables: dict[int, str] = field(default_factory=dict)  # addr -> class name
    globals: dict[int, str] = field(default_factory=dict)  # addr -> name
    duplicates: dict[int, list[Claim]] = field(default_factory=dict)


# Backwards-compatible alias (the old tools.source_model dataclass name).
MarkerClaim = Claim


def _parse_decl(lines: list[str], start: int) -> tuple[str, str]:
    """(name, prototype-head) parsed from the declaration at/after `start`."""
    for j in range(start, min(start + 3, len(lines))):
        line = lines[j].strip()
        if not line or line.startswith("//"):
            continue
        m = _DEF_RE.match(line)
        if not m:
            return "", ""
        name = m.group(1)
        if name.rsplit("::", 1)[-1].lstrip("~") in _NOT_NAMES:
            return "", ""
        # Join continuation lines until the parameter list closes.
        head = line
        k = j
        while head.count("(") > head.count(")") and k + 1 < len(lines) and k - j < 6:
            k += 1
            head += " " + lines[k].strip()
        head = head.split("{", 1)[0].rstrip().rstrip(";").rstrip()
        return name, " ".join(head.split())
    return "", ""


def _claim_name(kind: str, lines: list[str], marker_idx: int) -> tuple[str, str, str]:
    """(name, prototype, symbol) for a marker claim."""
    if kind == "FUNCTION":
        name, proto = _parse_decl(lines, marker_idx + 1)
        return name, proto, ""
    # SYNTHETIC/TEMPLATE/LIBRARY: convention comment line under the marker.
    # Mangled/linker spellings are symbols, never names — check them first.
    if marker_idx + 1 < len(lines):
        text = lines[marker_idx + 1].strip()
        m = _MANGLED_COMMENT_RE.match(text)
        if m:
            return "", "", m.group(1)
        m = _NAME_COMMENT_RE.match(text)
        if m:
            return m.group(1), "", ""
    return "", "", ""


def reviewed_identities(repo_root: Path) -> list[Claim]:
    path = repo_root / REVIEWED_CSV
    if not path.is_file():
        return []
    from tools.common.pipe_csv import read_pipe_rows

    out: list[Claim] = []
    for row in read_pipe_rows(path):
        raw = (row.get("address") or "").strip()
        try:
            addr = int(raw, 16)
        except ValueError:
            continue
        out.append(Claim(
            address=addr,
            kind="LIBRARY",
            file=REVIEWED_CSV,
            line=0,
            name=(row.get("name") or "").strip(),
            prototype=(row.get("prototype") or "").strip(),
            symbol=(row.get("symbol") or "").strip(),
            origin="reviewed",
        ))
    return out


def build_model(repo_root: Path, target: str = "IMPERIALISM") -> SourceModel:
    rx = function_marker_regex(target)
    model = SourceModel(target=target)
    per_addr: dict[int, list[Claim]] = {}

    for path in iter_files([str(repo_root / "src"), str(repo_root / "include")]):
        if is_generated_source_path(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = path.resolve().relative_to(repo_root.resolve()).as_posix()
        lines = text.splitlines()
        for i, line in enumerate(lines):
            m = rx.search(line)
            if m:
                kind = next((k for k in _KINDS if k in line.upper()), "FUNCTION")
                addr = int(m.group(1), 16)
                name, proto, symbol = _claim_name(kind, lines, i)
                claim = Claim(address=addr, kind=kind, file=rel, line=i + 1,
                              name=name, prototype=proto, symbol=symbol)
                per_addr.setdefault(addr, []).append(claim)
                continue
            vm = _VTABLE_RE.search(line)
            if vm and vm.group(1).upper() == target.upper():
                vaddr = int(vm.group(2), 16)
                for j in range(i + 1, min(i + 6, len(lines))):
                    cm = _CLASS_DECL_RE.match(lines[j])
                    if cm:
                        model.vtables.setdefault(vaddr, cm.group(1))
                        break
                continue
            gm = _GLOBAL_RE.search(line)
            if gm and gm.group(1).upper() == target.upper():
                gaddr = int(gm.group(2), 16)
                gname = (gm.group(3) or "").strip()
                if not gname and i + 1 < len(lines):
                    # Name comes from the following declaration: `Type g_name... =`.
                    dm = re.search(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?:=|;)",
                                   lines[i + 1])
                    if dm:
                        gname = dm.group(1)
                if gname:
                    model.globals.setdefault(gaddr, gname)

    for addr, claims in sorted(per_addr.items()):
        model.functions[addr] = claims[0]
        if len(claims) > 1:
            model.duplicates[addr] = claims

    # Reviewed library identities are LIBRARY claims; a source marker wins.
    for claim in reviewed_identities(repo_root):
        model.functions.setdefault(claim.address, claim)

    return model


# ---------------------------------------------------------------------------
# Compatibility views (the old tools.source_model API, single implementation)
# ---------------------------------------------------------------------------

def scan_marker_claims(repo_root: Path, target: str,
                       roots: tuple[str, ...] = ("src", "include")) -> list[Claim]:
    """Marker claims only (no reviewed rows), sorted — the old source_index view."""
    model = build_model(repo_root, target)
    out = [c for c in model.functions.values() if c.origin == "marker"]
    for claims in model.duplicates.values():
        for c in claims[1:]:
            out.append(c)
    out.sort(key=lambda c: (c.address, c.file, c.line))
    return out


def find_duplicate_claims(claims: list[Claim]) -> dict[int, list[Claim]]:
    by_addr: dict[int, list[Claim]] = {}
    for c in claims:
        by_addr.setdefault(c.address, []).append(c)
    return {a: cs for a, cs in by_addr.items() if len(cs) > 1}


def claimed_addresses(repo_root: Path, target: str = "IMPERIALISM") -> set[int]:
    """Addresses claimed by markers OR reviewed library identities."""
    return set(build_model(repo_root, target).functions)


def ownership_kind(kind: str) -> str:
    return "library" if kind == "LIBRARY" else "manual"


def ownership_view(repo_root: Path, target: str = "IMPERIALISM") -> dict[int, Claim]:
    """addr -> claim (markers + reviewed), the ownership authority."""
    return dict(build_model(repo_root, target).functions)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def model_to_json(model: SourceModel) -> dict:
    return {
        "target": model.target,
        "functions": [
            {
                "address": "0x{:08x}".format(c.address), "kind": c.kind,
                "file": c.file, "line": c.line, "name": c.name,
                "prototype": c.prototype, "symbol": c.symbol, "origin": c.origin,
            }
            for _a, c in sorted(model.functions.items())
        ],
        "vtables": [
            {"address": "0x{:08x}".format(a), "class": cls}
            for a, cls in sorted(model.vtables.items())
        ],
        "globals": [
            {"address": "0x{:08x}".format(a), "name": n}
            for a, n in sorted(model.globals.items())
        ],
    }


def write_model(repo_root: Path, target: str, gen_dir: Path) -> tuple[Path, SourceModel]:
    model = build_model(repo_root, target)
    gen_dir.mkdir(parents=True, exist_ok=True)
    out = gen_dir / MODEL_NAME
    out.write_text(json.dumps(model_to_json(model), indent=1) + "\n", encoding="utf-8")
    return out, model


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--gen-dir", default=DEFAULT_GEN_DIR)
    args = parser.parse_args()
    repo_root = repo_root_from_file(__file__, levels_up=1)
    out, model = write_model(repo_root, args.target,
                             resolve_repo_path(repo_root, args.gen_dir))
    marker_fns = sum(1 for c in model.functions.values() if c.origin == "marker")
    named = sum(1 for c in model.functions.values() if c.name)
    print(f"Wrote {out} ({marker_fns} marker claims, "
          f"{len(model.functions) - marker_fns} reviewed claims, {named} named, "
          f"{len(model.vtables)} vtables, {len(model.globals)} globals)")
    if model.duplicates:
        print("source-model FAILED: duplicate function-kind claims (one address, one owner):")
        for addr in sorted(model.duplicates):
            for c in model.duplicates[addr]:
                print("  0x{:08x} {} {}:{}".format(addr, c.kind, c.file, c.line))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
