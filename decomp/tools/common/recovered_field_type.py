"""Shared grammar for config/recovered_fields.csv field_type column."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class FieldKind(Enum):
    SCALAR = "scalar"
    POINTER = "pointer"
    VALUE_ARRAY = "value_array"
    POINTER_ARRAY = "pointer_array"


_SCALAR_SIZES: dict[str, int] = {
    "bool": 1,
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "byte": 1,
    "short": 2,
    "unsigned short": 2,
    "word": 2,
    "int": 4,
    "unsigned int": 4,
    "dword": 4,
    "uint": 4,
    "long": 4,
    "unsigned long": 4,
}

_INT_LIKE = frozenset({"int", "dword", "uint", "unsigned int"})


@dataclass(frozen=True)
class FieldTypeSpec:
    """Parsed recovered_fields field_type."""

    csv_text: str
    kind: FieldKind
    base: str
    count: Optional[int] = None
    is_class_pointer: bool = False

    @property
    def byte_length(self) -> int:
        if self.kind == FieldKind.POINTER:
            return 4
        if self.kind == FieldKind.POINTER_ARRAY:
            assert self.count is not None
            return 4 * self.count
        if self.kind == FieldKind.VALUE_ARRAY:
            assert self.count is not None
            return _scalar_byte_size(self.base) * self.count
        return _scalar_byte_size(self.base)


def _scalar_byte_size(base: str) -> int:
    key = base.strip().lower()
    if key in _SCALAR_SIZES:
        return _SCALAR_SIZES[key]
    return 4


def _parse_count(count_s: str) -> int:
    count_s = count_s.strip()
    if count_s.lower().startswith("0x"):
        return int(count_s, 16)
    return int(count_s)


def parse_field_type(spec: str) -> FieldTypeSpec | None:
    """Parse a recovered_fields field_type string."""
    raw = spec.strip()
    if not raw:
        return None

    ptr_array = re.fullmatch(r"([\w\s]+?)\*\[([0-9a-fA-Fx]+)\]", raw)
    if ptr_array:
        base = ptr_array.group(1).strip()
        count = _parse_count(ptr_array.group(2))
        return FieldTypeSpec(raw, FieldKind.POINTER_ARRAY, base, count)

    value_array = re.fullmatch(r"([\w\s]+?)\[([0-9a-fA-Fx]+)\]", raw)
    if value_array:
        base = value_array.group(1).strip()
        lower = base.lower()
        if lower not in _SCALAR_SIZES:
            return None
        count = _parse_count(value_array.group(2))
        return FieldTypeSpec(raw, FieldKind.VALUE_ARRAY, lower, count)

    if raw.endswith("*"):
        base = raw[:-1].strip()
        return FieldTypeSpec(raw, FieldKind.POINTER, base)

    lower = raw.lower()
    if lower in _SCALAR_SIZES:
        return FieldTypeSpec(raw, FieldKind.SCALAR, lower)

    # Legacy: bare class name denotes a pointer field.
    return FieldTypeSpec(raw, FieldKind.POINTER, raw, is_class_pointer=True)


def parse_data_field_type(type_part: str) -> FieldTypeSpec | None:
    """Parse recovered_data field type fragment (e.g. dword, dword[6])."""
    return parse_field_type(type_part.strip())


def to_csv_type(
    base: str,
    *,
    is_ptr: bool = False,
    array_count: int | None = None,
    pointer_array: bool = False,
) -> str:
    """Build a recovered_fields field_type from C++ member shape."""
    name = base.strip()
    if array_count is not None:
        count_s = f"0x{array_count:x}" if array_count > 9 else str(array_count)
        if is_ptr or pointer_array:
            return f"{name}*[{count_s}]"
        return f"{name}[{count_s}]"
    if is_ptr:
        if name.lower() in _INT_LIKE:
            return f"{name}*"
        if name.lower() == "void":
            return "void*"
        return name
    lower = name.lower()
    if lower in _SCALAR_SIZES:
        if lower in ("dword", "uint"):
            return "int"
        if lower == "word":
            return "short"
        if lower == "byte":
            return "unsigned char"
        return lower
    return name
