#!/usr/bin/env python3
"""Generate linkable function stubs from config/symbols.csv.

By default this writes chunked sources under `src/autogen/stubs/` to avoid
old MSVC line/debug section limits with very large single translation units.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

ANNOTATION_RE_TEMPLATE = (
    r"//\s*(?:FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY)\s*:\s*{target}\s+"
    r"(?:0x)?([0-9a-fA-F]+)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--symbols-csv", default="config/symbols.csv")
    parser.add_argument(
        "--name-overrides",
        default="config/name_overrides.csv",
        help="Optional pipe-delimited file: address|name|prototype",
    )
    parser.add_argument(
        "--output-dir",
        default="src/autogen/stubs",
        help="Directory for generated stub chunks (default: src/autogen/stubs)",
    )
    parser.add_argument(
        "--max-functions-per-file",
        type=int,
        default=500,
        help="Maximum generated stubs per .cpp chunk file (default: 500)",
    )
    parser.add_argument("--source-dir", default="src")
    parser.add_argument(
        "--use-prototypes",
        action="store_true",
        help=(
            "Attempt to emit signatures from 'prototype' column where possible. "
            "Disabled by default to keep generated code maximally buildable."
        ),
    )
    parser.add_argument(
        "--annotation-kind",
        default="FUNCTION",
        choices=("STUB", "FUNCTION"),
        help="Annotation marker to emit for generated stubs.",
    )
    return parser.parse_args()


def path_in_dir(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def load_old_generated_cpp_files(manifest_path: Path) -> list[str]:
    if not manifest_path.is_file():
        return []
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        files = payload.get("generated_cpp_files", [])
        if isinstance(files, list):
            return [str(x) for x in files]
    except Exception:
        pass
    return []


def clean_old_outputs(output_dir: Path, manifest_path: Path) -> None:
    old_relpaths = load_old_generated_cpp_files(manifest_path)
    for relpath in old_relpaths:
        full = output_dir / relpath
        if full.is_file():
            full.unlink()
    for path in sorted(output_dir.rglob("*"), reverse=True):
        if path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass


def collect_defined_addresses(target: str, source_dir: Path, output_dir: Path) -> set[int]:
    annotation_re = re.compile(
        ANNOTATION_RE_TEMPLATE.format(target=re.escape(target)), re.IGNORECASE
    )
    addresses: set[int] = set()
    if not source_dir.is_dir():
        return addresses

    legacy_single_file = output_dir.parent / "stubs.cpp"
    for path in source_dir.rglob("*.cpp"):
        # Ignore generated stub chunks, they should not suppress regeneration.
        if path_in_dir(path, output_dir):
            continue
        if path.resolve() == legacy_single_file.resolve():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in annotation_re.finditer(text):
            addresses.add(int(match.group(1), 16))
    return addresses


def sanitize_identifier(name: str, addr: int) -> str:
    ident = name.replace("::", "__")
    ident = re.sub(r"[^A-Za-z0-9_]", "_", ident)
    ident = re.sub(r"_+", "_", ident).strip("_")
    if not ident:
        ident = "sub_{:08X}".format(addr)
    if ident[0].isdigit():
        ident = "_" + ident
    return ident


def dedupe_identifier(ident: str, addr: int, seen: set[str]) -> str:
    if ident not in seen:
        seen.add(ident)
        return ident
    deduped = "{}_{:08X}".format(ident, addr)
    seen.add(deduped)
    return deduped


def sanitize_prototype(proto: str) -> str:
    # Keep one-line signatures and avoid CSV/newline breakage from upstream text.
    return " ".join(proto.replace("|", " ").split())


def prototype_usable(proto: str) -> bool:
    # Conservative filter: reject member/template/complex forms that frequently fail without
    # full type/class declarations.
    forbidden_tokens = ("::", "<", ">", "operator", "{", "}")
    return "(" in proto and ")" in proto and not any(t in proto for t in forbidden_tokens)


def build_signature(ident: str, prototype: str, use_prototypes: bool) -> str:
    if use_prototypes and prototype and prototype_usable(prototype):
        candidate = prototype.rstrip().rstrip(";")
        # Replace trailing function-name token if present.
        candidate = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(", "{}(".format(ident), candidate, count=1)
        return candidate
    return "undefined4 {}(void)".format(ident)


def function_name_from_prototype(prototype: str) -> str:
    if not prototype:
        return ""
    matches = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", prototype)
    if not matches:
        return ""
    return matches[-1]


def signature_returns_void(signature: str) -> bool:
    head = signature.split("(", 1)[0].strip().lower()
    return head.startswith("void ")


def parse_rows(csv_path: Path) -> list[dict[str, str]]:
    with csv_path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        return list(reader)


def parse_override_rows(csv_path: Path) -> dict[int, tuple[str, str]]:
    if not csv_path.is_file():
        return {}
    with csv_path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        rows: dict[int, tuple[str, str]] = {}
        for row in reader:
            addr_text = (row.get("address") or "").strip()
            if not addr_text:
                continue
            addr = int(addr_text, 16)
            name = " ".join((row.get("name") or "").replace("|", " ").split())
            prototype = sanitize_prototype((row.get("prototype") or "").strip())
            rows[addr] = (name, prototype)
        return rows


def chunked_rows(
    rows: list[tuple[int, str, str]], max_functions_per_file: int
) -> list[list[tuple[int, str, str]]]:
    if max_functions_per_file <= 0 or len(rows) <= max_functions_per_file:
        return [rows]
    chunks: list[list[tuple[int, str, str]]] = []
    for i in range(0, len(rows), max_functions_per_file):
        chunks.append(rows[i : i + max_functions_per_file])
    return chunks


def render_chunk(
    chunk_rows: list[tuple[int, str, str]],
    seen_idents: set[str],
    target: str,
    annotation_kind: str,
    use_prototypes: bool,
) -> str:
    out: list[str] = []
    out.append("// AUTOGENERATED FILE. DO NOT EDIT.\n")
    out.append("// Regenerate with: uv run python tools/stubgen.py\n\n")
    out.append('#include "decomp_types.h"\n\n')

    for address, name, prototype in chunk_rows:
        proto_name = function_name_from_prototype(prototype)
        raw_name = proto_name or name or "sub_{:08X}".format(address)
        ident = sanitize_identifier(raw_name, address)
        ident = dedupe_identifier(ident, address, seen_idents)
        signature = build_signature(ident, prototype, use_prototypes)

        if name:
            out.append("// ghidra_name {}\n".format(name))
        if prototype:
            out.append("// ghidra_proto {}\n".format(prototype))
        out.append("// {}: {} 0x{:08x}\n".format(annotation_kind, target, address))
        out.append("{}\n".format(signature))
        out.append("{\n")
        if signature_returns_void(signature):
            out.append("  return;\n")
        else:
            out.append("  return 0;\n")
        out.append("}\n\n")
    return "".join(out)


def main() -> int:
    args = parse_args()
    target = args.target
    csv_path = Path(args.symbols_csv)
    overrides_path = Path(args.name_overrides)
    output_dir = Path(args.output_dir)
    source_dir = Path(args.source_dir)

    if not csv_path.is_file():
        raise SystemExit("Missing symbols CSV: {}".format(csv_path))

    defined_addresses = collect_defined_addresses(
        target=target, source_dir=source_dir, output_dir=output_dir
    )
    rows = parse_rows(csv_path)
    overrides = parse_override_rows(overrides_path)

    function_rows: list[tuple[int, str, str]] = []
    for row in rows:
        row_type = (row.get("type") or "").strip().lower()
        if row_type not in {"function", "template", "synthetic", "library", "stub"}:
            continue
        address_text = (row.get("address") or "").strip()
        if not address_text:
            continue
        address = int(address_text, 16)
        if address in defined_addresses:
            continue
        name = (row.get("name") or "").strip()
        prototype = sanitize_prototype((row.get("prototype") or "").strip())
        override = overrides.get(address)
        if override is not None:
            if override[0]:
                name = override[0]
            if override[1]:
                prototype = override[1]
        function_rows.append((address, name, prototype))

    function_rows.sort(key=lambda r: r[0])
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "_manifest.json"
    clean_old_outputs(output_dir=output_dir, manifest_path=manifest_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    chunks = chunked_rows(function_rows, args.max_functions_per_file)
    seen_idents: set[str] = set()
    generated_files: list[str] = []

    for idx, chunk in enumerate(chunks, start=1):
        relpath = "stubs_part{:03d}.cpp".format(idx)
        out_file = output_dir / relpath
        out_file.write_text(
            render_chunk(
                chunk_rows=chunk,
                seen_idents=seen_idents,
                target=target,
                annotation_kind=args.annotation_kind,
                use_prototypes=args.use_prototypes,
            ),
            encoding="utf-8",
        )
        generated_files.append(relpath)

    manifest_payload = {
        "generated_cpp_files": generated_files,
        "chunk_count": len(generated_files),
        "stub_count": len(function_rows),
        "target": target,
        "max_functions_per_file": args.max_functions_per_file,
    }
    manifest_path.write_text(
        json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    legacy_single_file = output_dir.parent / "stubs.cpp"
    if legacy_single_file.is_file():
        legacy_single_file.unlink()

    print(
        "Wrote {} chunk file(s) in {} ({} stubs)".format(
            len(generated_files), output_dir, len(function_rows)
        )
    )
    if overrides:
        print("Applied {} name override(s)".format(len(overrides)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
