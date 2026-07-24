#!/usr/bin/env python3
"""Compiler-backed declaration index for the manual C++ source (Clang AST).

The signature projector must not infer a function's kind (static vs instance
member vs namespace-scoped free function) from punctuation — an out-of-class
definition head does not repeat `static`, and `Ns::fn` is indistinguishable from
`Class::method` by text alone. This module builds an authoritative index from a
real Clang parse of the game headers, keyed by qualified name:

    qualified_name -> [DeclInfo(kind, is_static, ret, params, has_this), ...]

`kind` is one of: constructor | destructor | instance_method | static_method |
namespace_function | free_function. Overloads share a name -> a list (the caller
disambiguates by parameter count). Free functions defined only in a .cpp (no
header declaration) are absent; the caller falls back to its textual parse for
those, where the punctuation answer (no `::` => free_function => __cdecl) is
already correct.

Parsing uses the vendored MSVC500/MFC headers in clang-cl C++ mode. Clang emits
a partial AST on the handful of parse errors, which is fine — we only read
declaration shapes. The full AST is large, so the CLI writes a COMPACT index
artifact that consumers load instead of re-parsing.

  uv run python -m tools.clang_ast_index --out build-msvc500/generated/decl_index.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path

_METHOD_KINDS = {"CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl", "FunctionDecl"}
_SCOPE_KINDS = {"NamespaceDecl", "CXXRecordDecl", "ClassTemplateDecl"}


def game_header_include_paths(repo_root: Path) -> list[str]:
    """Return every game header using the canonical include-root spelling."""
    include_root = repo_root / "include"
    return sorted(
        path.relative_to(include_root).as_posix()
        for path in (include_root / "game").rglob("*.h")
    )


@dataclass(frozen=True)
class DeclInfo:
    kind: str            # constructor|destructor|instance_method|static_method|namespace_function|free_function
    is_static: bool
    ret: str             # return type spelling ("" for ctor/dtor)
    params: tuple        # tuple[str, ...] of parameter type spellings
    has_this: bool       # implicit this present (non-static member)


def _vendored_include_flags(repo_root: Path) -> list[str]:
    v = repo_root / "vendor" / "msvc500" / "headers"
    flags = ["/Iinclude", "/Iinclude/game"]
    for sub in ("include", "mfc/include", "atl/include"):
        p = v / sub
        if p.is_dir():
            flags.append(f"/I{p}")
    return flags


def _emit_ast_json(repo_root: Path, clang: str = "clang++") -> Path:
    """Parse an umbrella TU of every game header; return the AST JSON temp path."""
    if shutil.which(clang) is None and clang == "clang++":
        versioned = sorted(
            Path("/usr/bin").glob("clang++-[0-9]*"),
            key=lambda path: tuple(int(part) for part in path.name.split("-")[1:]),
            reverse=True,
        )
        if versioned:
            clang = str(versioned[0])
    headers = game_header_include_paths(repo_root)
    umbrella = tempfile.NamedTemporaryFile(
        "w", suffix=".cpp", delete=False, dir=tempfile.gettempdir())
    for header in headers:
        umbrella.write(f'#include "{header}"\n')
    umbrella.close()
    ast_path = Path(tempfile.mkstemp(suffix=".ast.json")[1])
    cmd = [clang, "--driver-mode=cl", "/TP", "-fsyntax-only",
           "-Xclang", "-ast-dump=json", "/DIMPERIALISM_LINT",
           *_vendored_include_flags(repo_root), umbrella.name]
    with open(ast_path, "wb") as out:
        # clang exits nonzero on the partial-parse errors but still emits the AST.
        subprocess.run(cmd, cwd=repo_root, stdout=out, stderr=subprocess.DEVNULL, check=False)
    os.unlink(umbrella.name)
    return ast_path


def _return_type(node: dict, params: list) -> str:
    """Best-effort return-type spelling from the decl's function type."""
    q = (node.get("type") or {}).get("qualType", "")
    # qualType looks like "void (short, int)" — take the head before the first "(".
    depth = 0
    for i, ch in enumerate(q):
        if ch == "(":
            return q[:i].strip()
        if ch in "<[":
            depth += 1
        elif ch in ">]":
            depth -= 1
    return q.strip()


def _params_of(node: dict) -> list:
    out = []
    for c in node.get("inner", []) or []:
        if c.get("kind") == "ParmVarDecl":
            out.append(((c.get("type") or {}).get("qualType", "") or "").strip())
    return out


def _walk(node: dict, scope: list, index: dict) -> None:
    kind = node.get("kind")
    name = node.get("name")
    if kind in _SCOPE_KINDS and name:
        for c in node.get("inner", []) or []:
            _walk(c, scope + [name], index)
        return
    if kind in _METHOD_KINDS and name is not None:
        is_static = node.get("storageClass") == "static"
        in_record = kind != "FunctionDecl"  # method/ctor/dtor are always members
        if kind == "CXXConstructorDecl":
            ek, has_this = "constructor", True
        elif kind == "CXXDestructorDecl":
            ek, has_this = "destructor", True
        elif kind == "CXXMethodDecl":
            ek = "static_method" if is_static else "instance_method"
            has_this = not is_static
        else:  # FunctionDecl
            if is_static:
                ek = "static_method"
            elif scope:
                ek = "namespace_function"
            else:
                ek = "free_function"
            has_this = False
        ret = "" if kind in ("CXXConstructorDecl", "CXXDestructorDecl") else _return_type(node, [])
        qn = "::".join([s for s in scope if s] + [name])
        info = DeclInfo(ek, is_static, ret, tuple(_params_of(node)), has_this)
        index.setdefault(qn, [])
        if info not in index[qn]:
            index[qn].append(info)
    for c in node.get("inner", []) or []:
        _walk(c, scope, index)


def build_decl_index(repo_root: Path, *, ast_json_path: Path | None = None,
                     clang: str = "clang++") -> dict:
    """qualified_name -> [DeclInfo, ...] from a Clang parse of the game headers."""
    ast_path = ast_json_path or _emit_ast_json(repo_root, clang=clang)
    try:
        ast = json.loads(ast_path.read_text())
    finally:
        if ast_json_path is None and ast_path.exists():
            ast_path.unlink()
    index: dict = {}
    _walk(ast, [], index)
    return index


def load_compact_index(path: Path) -> dict:
    """Load a written compact index into {name: [DeclInfo, ...]}."""
    raw = json.loads(Path(path).read_text())
    return {name: [DeclInfo(**{**d, "params": tuple(d["params"])}) for d in decls]
            for name, decls in raw.items()}


def write_compact_index(index: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serial = {name: [asdict(d) for d in decls] for name, decls in sorted(index.items())}
    for decls in serial.values():
        for d in decls:
            d["params"] = list(d["params"])
    path.write_text(json.dumps(serial, indent=0) + "\n", encoding="utf-8")


def main() -> int:
    from tools.common.repo import repo_root_from_file

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", default="build-msvc500/generated/decl_index.json")
    p.add_argument("--clang", default="clang++")
    p.add_argument("--ast-json", help="Reuse an existing AST JSON dump instead of re-parsing.")
    args = p.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=1)
    index = build_decl_index(
        repo_root,
        ast_json_path=Path(args.ast_json) if args.ast_json else None,
        clang=args.clang)
    out = Path(args.out)
    write_compact_index(index, out)

    kinds: dict = {}
    for decls in index.values():
        for d in decls:
            kinds[d.kind] = kinds.get(d.kind, 0) + 1
    print(f"decl index: {len(index)} qualified names -> {out}")
    print("  by kind: " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
