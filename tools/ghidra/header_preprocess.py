"""pcpp + cxxheaderparser pipeline for include/game/*.h."""

from __future__ import annotations

import re
from pathlib import Path

from cxxheaderparser.preprocessor import make_pcpp_preprocessor
from cxxheaderparser.simple import parse_string
from cxxheaderparser.types import Array, FundamentalSpecifier, NameSpecifier, Pointer, Type

from tools.common.repo import repo_root_from_file

REPO = repo_root_from_file(__file__)
INCLUDE_DIR = REPO / "include"
INCLUDE_GAME = INCLUDE_DIR / "game"
STUB_INCLUDE_DIR = REPO / "tools" / "ghidra" / "header_parse_stubs"


def default_include_paths() -> list[str]:
    return [str(STUB_INCLUDE_DIR), str(INCLUDE_DIR), str(INCLUDE_GAME)]


def make_header_preprocessor() -> object:
    """Build the repo-standard pcpp preprocessor (always-on)."""
    return make_pcpp_preprocessor(
        defines=["__cplusplus 199711L"],
        include_paths=default_include_paths(),
    )


def preprocess_header(path: Path, preprocessor: object | None = None) -> str:
    pre = preprocessor or make_header_preprocessor()
    return pre(str(path.resolve()), path.read_text(encoding="utf-8"))


def parse_header_file(path: Path, preprocessor: object | None = None):
    """Return cxxheaderparser ParsedData for a header path."""
    text = preprocess_header(path, preprocessor)
    return parse_string(text, filename=str(path.resolve()))


def class_name_of(scope) -> str:
    return scope.class_decl.typename.segments[-1].name


def base_class_names(scope) -> list[str]:
    names: list[str] = []
    for base in scope.class_decl.bases:
        seg = base.typename.segments[-1]
        if isinstance(seg, NameSpecifier):
            names.append(seg.name)
    return names


def fundamental_name(type_: Type) -> str | None:
    seg = type_.typename.segments[-1]
    if isinstance(seg, FundamentalSpecifier):
        return seg.name
    return None


def class_type_name(type_: Type) -> str | None:
    seg = type_.typename.segments[-1]
    if isinstance(seg, NameSpecifier):
        return seg.name
    return None


_ARRAY_SIZE_EXPR = re.compile(
    r"^\s*0x([0-9a-fA-F]+)\s*-\s*0x([0-9a-fA-F]+)\s*$", re.IGNORECASE
)


def array_size_value(type_) -> int | None:
    if not isinstance(type_, Array):
        return None
    tokens = getattr(type_.size, "tokens", None)
    if not tokens:
        return None
    raw = "".join(token.value for token in tokens).replace(" ", "")
    expr = _ARRAY_SIZE_EXPR.match(raw)
    if expr:
        return int(expr.group(1), 16) - int(expr.group(2), 16)
    try:
        return int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    except ValueError:
        return None


def type_to_cpp_shape(type_) -> tuple[str, bool, int | None, bool]:
    """Return (base_name, is_ptr, array_count, pointer_array)."""
    if isinstance(type_, Array):
        inner_base, inner_ptr, _, inner_ptr_array = type_to_cpp_shape(type_.array_of)
        count = array_size_value(type_)
        if isinstance(type_.array_of, Pointer):
            return inner_base, True, count, True
        return inner_base, inner_ptr, count, inner_ptr_array
    if isinstance(type_, Pointer):
        inner = type_.ptr_to
        if fundamental := fundamental_name(inner):
            return fundamental, True, None, False
        if cls := class_type_name(inner):
            return cls, True, None, False
        return "void", True, None, False
    if fundamental := fundamental_name(type_):
        return fundamental, False, None, False
    if cls := class_type_name(type_):
        return cls, False, None, False
    return "int", False, None, False
