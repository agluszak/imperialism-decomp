#!/usr/bin/env python3
"""Durable class model: Clang AST semantics + MSVC500 layout-oracle physical truth.

The Ghidra DB's game-class datatypes are mostly empty 1-byte stubs (see the
datatype-hygiene work): they carry a name but no layout, so nothing downstream may
trust their size. This module builds the real model in two strictly separated
layers:

  1. **Semantic source — the Clang AST** (this module): which records exist, their
     base-class edges, field names/type spellings/array counts, bitfield-ness,
     virtual-ness. Clang is authoritative for *declarations only*; its host layout
     is never used.
  2. **Physical layout — the MSVC500 layout oracle** (`tools.layout_oracle`): a
     generated TU compiled and executed by the ACTUAL VC5 toolchain container,
     printing sizeof / base offsets / field offsets+sizes. Layout facts are build
     evidence from the real compiler, never host-clang guesses and never
     hand-written metadata.

The RecordModel is keyed by fully-qualified name. Only records DEFINED in the
repo's own headers (include/) are modelled — MFC/system records come from the
reviewed MFC datatype pack and are out of scope here.

  uv run python -m tools.class_model --out build-msvc500/generated/record_model.json
  uv run python -m tools.class_model --ast-json <cached.ast.json> --out ...
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

from tools.clang_ast_index import _emit_ast_json


@dataclass(frozen=True)
class FieldInfo:
    name: str
    type: str              # canonical-ish spelling from the AST (semantic only)
    is_bitfield: bool = False
    array_count: int = 0   # 0 = not an array; N = constant array length


@dataclass(frozen=True)
class BaseInfo:
    type: str
    access: str = "public"
    is_virtual: bool = False


@dataclass
class RecordInfo:
    qualified_name: str
    tag: str               # class | struct | union
    file: str              # header path (repo-relative when under the repo)
    bases: list = field(default_factory=list)    # [BaseInfo]
    fields: list = field(default_factory=list)   # [FieldInfo]
    has_own_virtuals: bool = False               # declares a virtual member itself


_RECORD_KINDS = {"CXXRecordDecl"}
_SCOPE_KINDS = {"NamespaceDecl", "CXXRecordDecl", "ClassTemplateDecl"}


def _array_count(qual_type: str) -> int:
    """`short [5]` -> 5; nested/multi-dim collapse to total element count."""
    import re
    counts = re.findall(r"\[(\d+)\]", qual_type)
    n = 1
    for c in counts:
        n *= int(c)
    return n if counts else 0


def _walk_records(node: dict, scope: list, cur_file: list, out: dict,
                  include_prefix: str, in_template: bool = False) -> None:
    """Depth-first walk tracking the current file (clang emits `loc.file` sparsely —
    only when it changes in document order), collecting complete record definitions
    whose defining header lives under `include_prefix`. Records inside a
    ClassTemplateDecl are the dependent template PATTERN — they have no concrete
    layout and are skipped (in_template)."""
    loc = node.get("loc") or {}
    f = loc.get("file") or (node.get("range", {}).get("begin", {}) or {}).get("file")
    if f:
        cur_file[0] = f

    kind = node.get("kind")
    name = node.get("name")

    if kind in _RECORD_KINDS and name and node.get("completeDefinition") and not in_template:
        qn = "::".join([s for s in scope if s] + [name])
        rec_file = cur_file[0] or ""
        # STRICT prefix match on the repo's own include dir. A substring test would
        # also match vendored SDK headers (vendor/msvc500/headers/include/...) and
        # leak system records (_DPCAPS, MIDL structs) into the game model.
        rel = None
        if rec_file.startswith(include_prefix):
            rel = rec_file
        elif f"/{include_prefix}" in rec_file and "vendor/" not in rec_file:
            rel = rec_file[rec_file.rindex(f"/{include_prefix}") + 1:]
        if rel is not None:
            rec = RecordInfo(
                qualified_name=qn,
                tag=node.get("tagUsed", "class"),
                file=rel,
            )
            for b in node.get("bases", []) or []:
                bt = (b.get("type") or {}).get("qualType", "").strip()
                rec.bases.append(BaseInfo(
                    type=bt, access=b.get("access", "public"),
                    is_virtual=bool(b.get("isVirtual"))))
            for c in node.get("inner", []) or []:
                ck = c.get("kind")
                if ck == "FieldDecl" and c.get("name") and not c.get("isInvalid"):
                    qt = (c.get("type") or {}).get("qualType", "")
                    rec.fields.append(FieldInfo(
                        name=c["name"], type=qt,
                        is_bitfield=bool(c.get("isBitfield")),
                        array_count=_array_count(qt)))
                elif ck in ("CXXMethodDecl", "CXXDestructorDecl") and c.get("virtual"):
                    rec.has_own_virtuals = True
            # Last complete definition wins (redefinitions across the umbrella are
            # identical by ODR; clang emits one).
            out[qn] = rec

    if kind in _SCOPE_KINDS and name:
        child_in_template = in_template or kind == "ClassTemplateDecl"
        for c in node.get("inner", []) or []:
            _walk_records(c, scope + [name], cur_file, out, include_prefix, child_in_template)
        return
    for c in node.get("inner", []) or []:
        _walk_records(c, scope, cur_file, out, include_prefix, in_template)


def build_record_model(repo_root: Path, *, ast_json_path: Path | None = None,
                       clang: str = "clang++", include_prefix: str = "include/") -> dict:
    """qualified_name -> RecordInfo for records defined under `include_prefix`."""
    ast_path = ast_json_path or _emit_ast_json(repo_root, clang=clang)
    try:
        ast = json.loads(ast_path.read_text())
    finally:
        if ast_json_path is None and ast_path.exists():
            ast_path.unlink()
    out: dict = {}
    _walk_records(ast, [], [""], out, include_prefix)
    return out


def write_record_model(model: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serial = {}
    for qn, rec in sorted(model.items()):
        d = asdict(rec)
        serial[qn] = d
    path.write_text(json.dumps(serial, indent=1) + "\n", encoding="utf-8")


def load_record_model(path: Path) -> dict:
    raw = json.loads(Path(path).read_text())
    out = {}
    for qn, d in raw.items():
        rec = RecordInfo(qualified_name=d["qualified_name"], tag=d["tag"], file=d["file"],
                         has_own_virtuals=d.get("has_own_virtuals", False))
        rec.bases = [BaseInfo(**b) for b in d.get("bases", [])]
        rec.fields = [FieldInfo(**f) for f in d.get("fields", [])]
        out[qn] = rec
    return out


def main() -> int:
    from tools.common.repo import repo_root_from_file

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", default="build-msvc500/generated/record_model.json")
    p.add_argument("--ast-json", help="Reuse an existing AST JSON dump instead of re-parsing.")
    p.add_argument("--clang", default="clang++")
    args = p.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=1)
    model = build_record_model(
        repo_root,
        ast_json_path=Path(args.ast_json) if args.ast_json else None,
        clang=args.clang)
    out = Path(args.out)
    write_record_model(model, out)

    n_fields = sum(len(r.fields) for r in model.values())
    n_bases = sum(len(r.bases) for r in model.values())
    n_virt = sum(1 for r in model.values() if r.has_own_virtuals)
    print(f"record model: {len(model)} records ({n_fields} fields, {n_bases} base edges, "
          f"{n_virt} with own virtuals) -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
