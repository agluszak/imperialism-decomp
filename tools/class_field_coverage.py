#!/usr/bin/env python3
"""Read-only semantic field-quality report over the class model.

The class model (`tools.class_model` + `tools.layout_oracle`) already gets sizes
and offsets right for every modeled class, but a field being AT the right offset
says nothing about whether its declared name/type actually carries semantic
meaning: `int field10;` occupies the correct 4 bytes but tells a reader nothing.

This is a pure measurement pass over `record_model.json` (declared field name +
type text, from the Clang AST) and `layout_oracle.json` (offset/size, from the
real MSVC500 compiler) — it writes nothing to source or the Ghidra DB.

Per class, every own field's bytes are bucketed by TYPE quality into exactly one
of:

  semantically_typed_bytes — a real (non-void, non-undefined) type, whether a
                              primitive or a class/struct, with a non-weak name
  primitive_unknown_bytes  — a primitive (int/short/char/...) with a weak name
                              (`fieldXX`) — we know the size, not the meaning
  opaque_pointer_bytes     — `void*` (any name) — the ABI is right, the pointee
                              is not
  padding_bytes            — name matches `pad`/`padding` (asserted inert filler)
  undefined_bytes          — a raw `undefined`/`undefined1`/`UNKNOWN` Ghidra
                              placeholder type

A field is additionally flagged WEAK (contributing to `weak_field_count`) when
its name matches `field(_0x)?[0-9A-F]*` / `pad(ding)?...`, or its type is
`void*`, or its type is an `undefined*` placeholder — independent of the byte
bucket above (a `TFoo* field10;` is a weak NAME on an otherwise well-typed
pointer, for example).

`reference_weight` sums, over every weak field, how many times its identifier
appears across the whole `include/`+`src/` tree — a single repo-wide index
(built once) is used for every class, which means two unrelated classes that
happen to share a weak field name (e.g. two different `field10`s) will each see
the SAME reference count. That is an accepted, documented imprecision of this
heuristic ranking pass (not a hard correctness gate): it is cheap, fully
deterministic, and still gives directionally-useful signal for "how much live
code touches bytes we don't understand yet" — do not read `reference_weight` as
an exact per-field call-site count.

Writes build-msvc500/evidence/class_field_coverage.csv with columns:
  class, size, inherited_bytes, semantically_typed_bytes, primitive_unknown_bytes,
  opaque_pointer_bytes, padding_bytes, undefined_bytes, weak_field_count,
  reference_weight

Usage:
  uv run python -m tools.class_field_coverage
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

_WEAK_NAME_RE = re.compile(r"^(field|pad|padding)(_0x)?[0-9A-Fa-f]*$", re.IGNORECASE)
_PAD_NAME_RE = re.compile(r"^pad(ding)?", re.IGNORECASE)
_UNDEFINED_TYPE_RE = re.compile(r"^(const\s+)?undefined\d*$|^UNKNOWN$", re.IGNORECASE)
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_PRIMITIVE_TYPES = {
    "void", "bool", "BOOL", "char", "signed char", "unsigned char", "byte",
    "short", "signed short", "unsigned short", "WORD", "int", "signed int",
    "unsigned int", "UINT", "DWORD", "long", "signed long", "unsigned long",
    "float", "double", "wchar_t", "long long", "unsigned long long",
}


def is_weak_name(name: str) -> bool:
    return bool(_WEAK_NAME_RE.match(name))


def is_pad_name(name: str) -> bool:
    return bool(_PAD_NAME_RE.match(name))


def _strip_cv(type_text: str) -> str:
    return re.sub(r"\b(const|volatile)\b", " ", type_text).strip()


def is_pointer_type(type_text: str) -> bool:
    return _strip_cv(type_text).rstrip().endswith("*")


def pointee_type(type_text: str) -> str:
    t = _strip_cv(type_text).rstrip()
    while t.endswith("*"):
        t = t[:-1].rstrip()
    return t


def is_void_pointer(type_text: str) -> bool:
    return is_pointer_type(type_text) and pointee_type(type_text) in ("void", "")


def is_undefined_type(type_text: str) -> bool:
    base = pointee_type(type_text) if is_pointer_type(type_text) else _strip_cv(type_text)
    return bool(_UNDEFINED_TYPE_RE.match(base))


def is_primitive_value_type(type_text: str) -> bool:
    """True for a BY-VALUE primitive (not a pointer, not a class/struct)."""
    if is_pointer_type(type_text):
        return False
    return _strip_cv(type_text) in _PRIMITIVE_TYPES


def classify_field(name: str, type_text: str) -> tuple[str, bool]:
    """Return (byte_bucket, is_weak) for one field.

    byte_bucket is exactly one of: semantically_typed_bytes,
    primitive_unknown_bytes, opaque_pointer_bytes, padding_bytes,
    undefined_bytes.
    """
    weak_name = is_weak_name(name)
    if is_pad_name(name):
        return "padding_bytes", True
    if is_undefined_type(type_text):
        return "undefined_bytes", True
    if is_void_pointer(type_text):
        return "opaque_pointer_bytes", True
    if is_primitive_value_type(type_text):
        if weak_name:
            return "primitive_unknown_bytes", True
        return "semantically_typed_bytes", False
    # Real pointer (to a named class) or a real by-value aggregate type.
    return "semantically_typed_bytes", weak_name


def build_reference_index(repo: Path) -> Counter:
    """One repo-wide identifier-occurrence count, built once and shared across
    every class (see module docstring for the accepted imprecision this implies)."""
    counter: Counter = Counter()
    for base_dir, pattern in (("include", "*.h"), ("src", "*.cpp")):
        root = repo / base_dir
        if not root.exists():
            continue
        for path in root.rglob(pattern):
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            for m in _IDENT_RE.finditer(text):
                counter[m.group(0)] += 1
    return counter


def load_record_fields(repo: Path) -> dict[str, dict[str, str]]:
    """class -> {field_name: declared_type_text} from the Clang AST record model."""
    data = json.loads((repo / "build-msvc500/generated/record_model.json").read_text())
    out: dict[str, dict[str, str]] = {}
    for name, rec in data.items():
        out[name] = {f["name"]: f["type"] for f in rec.get("fields", [])}
    return out


def load_layouts(repo: Path) -> dict:
    data = json.loads((repo / "build-msvc500/generated/layout_oracle.json").read_text())
    return data["layouts"]


def compute_inherited_bytes(layouts: dict, class_name: str) -> int:
    bases = layouts.get(class_name, {}).get("bases", {})
    total = 0
    for base_name in bases:
        base_layout = layouts.get(base_name)
        if base_layout is not None:
            total += base_layout.get("size", 0)
    return total


def build_report(repo: Path) -> list[dict]:
    layouts = load_layouts(repo)
    record_fields = load_record_fields(repo)
    ref_index = build_reference_index(repo)

    rows = []
    for class_name, layout in sorted(layouts.items()):
        size = layout.get("size", 0)
        inherited_bytes = compute_inherited_bytes(layouts, class_name)
        own_fields = layout.get("fields", {})
        declared_types = record_fields.get(class_name, {})

        buckets = {
            "semantically_typed_bytes": 0,
            "primitive_unknown_bytes": 0,
            "opaque_pointer_bytes": 0,
            "padding_bytes": 0,
            "undefined_bytes": 0,
        }
        weak_field_count = 0
        reference_weight = 0

        for field_name, field_info in own_fields.items():
            field_size = field_info.get("size", 0)
            type_text = declared_types.get(field_name, "undefined")
            bucket, is_weak = classify_field(field_name, type_text)
            buckets[bucket] += field_size
            if is_weak:
                weak_field_count += 1
                reference_weight += ref_index.get(field_name, 0)

        rows.append({
            "class": class_name,
            "size": size,
            "inherited_bytes": inherited_bytes,
            **buckets,
            "weak_field_count": weak_field_count,
            "reference_weight": reference_weight,
        })
    return rows


def main() -> int:
    from tools.common.repo import repo_root_from_file

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="build-msvc500/evidence/class_field_coverage.csv")
    parser.add_argument("--top", type=int, default=20, help="print the top-N ranked classes")
    args = parser.parse_args()

    repo = repo_root_from_file(__file__, levels_up=1)
    rows = build_report(repo)

    out = repo / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "class", "size", "inherited_bytes", "semantically_typed_bytes",
        "primitive_unknown_bytes", "opaque_pointer_bytes", "padding_bytes",
        "undefined_bytes", "weak_field_count", "reference_weight",
    ]
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    def active_weak_bytes(row: dict) -> int:
        return (
            row["primitive_unknown_bytes"] + row["opaque_pointer_bytes"] + row["undefined_bytes"]
        )

    ranked = sorted(
        rows, key=lambda r: active_weak_bytes(r) * max(r["reference_weight"], 1), reverse=True
    )

    print(f"Wrote {len(rows)} rows to {out}")
    print(f"\nTop {args.top} by (active weak bytes x reference weight):")
    for row in ranked[: args.top]:
        weak_bytes = active_weak_bytes(row)
        print(
            f"  {row['class']:<40} weak_bytes={weak_bytes:<5} "
            f"weak_fields={row['weak_field_count']:<3} refs={row['reference_weight']:<6} "
            f"score={weak_bytes * max(row['reference_weight'], 1)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
