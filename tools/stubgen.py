#!/usr/bin/env python3
"""Generate linkable function stubs into the build directory.

Stubs are disposable build inputs, not source: they are regenerated on every
`just build` from `config/original_entities.csv` minus the addresses claimed by manual
source markers (via tools.source_model). Nothing under the output directory is
committed.

Default output: build-msvc500/generated/stubs/ (compiled via CMake's
IMPERIALISM_GENERATED_DIR glob). Chunking is deterministic (address order,
fixed chunk size) — there is no committed state to keep diff-stable.

`--annotation-kind none` emits stubs without reccmp markers, for secondary
builds (lint) whose output must not double-register marker addresses.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.generate_symbols import generate_rows
from tools.source_model import build_model

DEFAULT_OUTPUT_DIR = "build-msvc500/generated/stubs"

STUBBED_ROW_TYPES = {"function", "template", "synthetic", "library", "stub"}

# Incremental-link (ILT) jmp-thunk table of the original binary: 5-byte `jmp target`
# linker stubs, never real functions. Legacy manual code still links against a few of
# these via the legacy free-function extern-thunk pattern, so their stub DEFINITIONS must
# exist — but they must NOT carry a `// FUNCTION:` annotation: an entity at a thunk
# address blocks reccmp's automatic thunk-to-target resolution (it broke 364/379
# vtable comparisons when annotated).
ILT_THUNK_RANGE = range(0x401000, 0x409AB6)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--symbols-csv", default="config/original_entities.csv")
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for generated stub chunks (default: {})".format(DEFAULT_OUTPUT_DIR),
    )
    parser.add_argument(
        "--max-functions-per-file",
        type=int,
        default=500,
        help="Maximum generated stubs per .cpp chunk file (default: 500)",
    )
    parser.add_argument(
        "--use-prototypes",
        action="store_true",
        help=(
            "Attempt to emit signatures from 'prototype' column where possible. "
            "Disabled by default to keep generated code maximally buildable."
        ),
    )
    parser.add_argument(
        "--chunk-prefix",
        default="stubs_part",
        help=(
            "Basename prefix for generated chunk files. Secondary builds (lint) must "
            "use a distinct prefix: reccmp resolves PDB line info by basename, and a "
            "same-named copy in another build dir ties the path-match score and drops "
            "the marker resolution."
        ),
    )
    parser.add_argument(
        "--annotation-kind",
        default="FUNCTION",
        choices=("STUB", "FUNCTION", "none"),
        help=(
            "Annotation marker to emit for generated stubs; 'none' emits no reccmp "
            "markers (secondary/lint builds)."
        ),
    )
    return parser.parse_args()


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
    whitelist = {
        "IsPointInsideHitRegion",
        "AssertQuickDrawFlag6A1DCCNonZero",
        "AssertQuickDrawFlag6A1DC8NonZero",
        "scanBracketExpressions",
        "BuildUiTextStyleDescriptor",
    }
    force_prototype = ident in whitelist or function_name_from_prototype(prototype) in whitelist
    if (use_prototypes or force_prototype) and prototype and prototype_usable(prototype):
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


def compute_stub_rows(
    repo_root: Path,
    target: str = "IMPERIALISM",
    symbols_csv: str = "config/original_entities.csv",
) -> list[tuple[int, str, str]]:
    """The stub set: generated-symbol function rows minus source-claimed addresses.

    Both inputs come from the central source model (tools.source_model) and the
    generated overlay (tools.generate_symbols) — one implementation, so the
    stub-count gate can never disagree with what generation would emit.
    """
    model = build_model(repo_root, target)
    claimed = set(model.functions)
    _fields, overlay_rows, _stats = generate_rows(
        repo_root, target, inventory=symbols_csv, model=model
    )

    rows: list[tuple[int, str, str]] = []
    for row in overlay_rows:
        row_type = (row.get("type") or "").strip().lower()
        if row_type not in STUBBED_ROW_TYPES:
            continue
        address_text = (row.get("address") or "").strip()
        if not address_text:
            continue
        address = int(address_text, 16)
        if address in claimed:
            continue
        name = (row.get("name") or "").strip()
        prototype = sanitize_prototype((row.get("prototype") or "").strip())
        rows.append((address, name, prototype))
    rows.sort(key=lambda r: r[0])
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
    out.append("// Regenerate with: uv run python -m tools.stubgen\n\n")
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
        if annotation_kind == "none":
            pass
        elif address in ILT_THUNK_RANGE:
            out.append(
                "// ILT thunk 0x{:08x} - unannotated on purpose (see ILT_THUNK_RANGE)\n".format(
                    address
                )
            )
        else:
            out.append("// {}: {} 0x{:08x}\n".format(annotation_kind, target, address))
        out.append("{}\n".format(signature))
        out.append("{\n")
        if signature_returns_void(signature):
            out.append("  return;\n")
        else:
            out.append("  return 0;\n")
        out.append("}\n\n")
    return "".join(out)


def clean_output_dir(output_dir: Path) -> None:
    if not output_dir.is_dir():
        return
    for path in output_dir.glob("*.cpp"):  # any prefix — stale copies must not linger
        path.unlink()
    manifest = output_dir / "_manifest.json"
    if manifest.is_file():
        manifest.unlink()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__, levels_up=1)
    output_dir = resolve_repo_path(repo_root, args.output_dir)

    # Stubs are build artifacts — refuse to write them into the source tree.
    src_dir = (repo_root / "src").resolve()
    try:
        output_dir.resolve().relative_to(src_dir)
        raise SystemExit(
            "Refusing to write generated stubs under src/ ({}). Stubs are build "
            "artifacts; use a build directory (default: {}).".format(
                output_dir, DEFAULT_OUTPUT_DIR
            )
        )
    except ValueError:
        pass

    function_rows = compute_stub_rows(
        repo_root,
        target=args.target,
        symbols_csv=args.symbols_csv,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    clean_output_dir(output_dir)

    seen_idents: set[str] = set()
    generated_files: list[str] = []
    for idx, chunk in enumerate(chunked_rows(function_rows, args.max_functions_per_file), start=1):
        relpath = "{}{:03d}.cpp".format(args.chunk_prefix, idx)
        (output_dir / relpath).write_text(
            render_chunk(
                chunk_rows=chunk,
                seen_idents=seen_idents,
                target=args.target,
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
        "target": args.target,
        "max_functions_per_file": args.max_functions_per_file,
    }
    (output_dir / "_manifest.json").write_text(
        json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        "Wrote {} chunk file(s) in {} ({} stubs)".format(
            len(generated_files), output_dir, len(function_rows)
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
