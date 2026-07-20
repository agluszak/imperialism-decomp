#!/usr/bin/env python3
"""Generate every build input in one process: model -> symbols -> stubs.

The single orchestrator behind `just generate` (and therefore `just build`).
It builds the central source model ONCE and threads the in-memory object
through every generator — no re-scan, no re-parse, no serialization contract
between steps:

  1. tools.source_model  -> <gen-dir>/source_model.json (+ duplicate validation)
  2. tools.ui_codegen    -> <gen-dir>/ui/*.cpp (+ _manifest.json)
  3. tools.generate_symbols -> <gen-dir>/symbols.csv (raw inventory + overlays)
  4. tools.stubgen       -> <gen-dir>/stubs/*.cpp (+ _manifest.json)

Exit is nonzero on duplicate claims. Secondary builds (lint) pass
--annotation-kind none and a distinct --chunk-prefix, same as stubgen's own CLI.
"""

from __future__ import annotations

import argparse

from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.generate_symbols import generate_rows
from tools.ghidra.merge_curated_symbols import write_symbols_csv
from tools.source_model import build_model, model_to_json
from tools.stubgen import write_stubs
from tools.ui_codegen import (
    load_recipes,
    load_ui_views,
    load_windows_recipes,
    validate as validate_ui_codegen,
)
from tools.ui_codegen import write_generated as write_generated_ui


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--gen-dir", default="build-msvc500/generated")
    parser.add_argument("--annotation-kind", default="FUNCTION",
                        choices=("STUB", "FUNCTION", "none"))
    parser.add_argument("--chunk-prefix", default="stubs_part")
    args = parser.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=1)
    gen_dir = resolve_repo_path(repo_root, args.gen_dir)
    gen_dir.mkdir(parents=True, exist_ok=True)

    # 1. The model, built once.
    model = build_model(repo_root, args.target)
    import json

    model_path = gen_dir / "source_model.json"
    model_path.write_text(json.dumps(model_to_json(model), indent=1) + "\n",
                          encoding="utf-8")
    marker_fns = sum(1 for c in model.functions.values() if c.origin == "marker")
    generated_fns = sum(1 for c in model.functions.values() if c.origin == "generated")
    print(f"Wrote {model_path} ({marker_fns} marker claims, "
          f"{generated_fns} generated claims, "
          f"{len(model.functions) - marker_fns - generated_fns} reviewed claims, "
          f"{len(model.vtables)} vtables, {len(model.globals)} globals)")
    if model.duplicates:
        print("generate FAILED: duplicate function-kind claims (one address, one owner):")
        for addr in sorted(model.duplicates):
            for c in model.duplicates[addr]:
                print("  0x{:08x} {} {}:{}".format(addr, c.kind, c.file, c.line))
        return 1

    # 2. Resource-driven UI factory TUs, from committed IR + Windows recipes.
    ui_recipes = load_recipes(repo_root)
    ui_views = load_ui_views(repo_root)
    ui_windows_recipes = load_windows_recipes(repo_root)
    ui_errors = validate_ui_codegen(
        repo_root, ui_recipes, ui_views, ui_windows_recipes
    )
    if ui_errors:
        print("generate FAILED: UI codegen validation:")
        for error in ui_errors:
            print(f"  - {error}")
        return 1
    ui_manifest = write_generated_ui(
        repo_root,
        gen_dir / "ui",
        ui_recipes,
        ui_views,
        ui_windows_recipes,
        annotation_kind=args.annotation_kind,
    )
    print(f"Wrote {len(ui_manifest['files'])} resource-driven UI factory TUs")

    # 3. The generated symbol table, from the same model object.
    fieldnames, rows, stats = generate_rows(repo_root, args.target, model=model)
    symbols_path = gen_dir / "symbols.csv"
    write_symbols_csv(symbols_path, fieldnames, rows)
    print(
        f"Wrote {symbols_path} ({len(rows)} rows; dropped {stats['dropped']} at "
        f"source-VTABLE addresses and {stats['dropped_interior']} inside verified "
        f"vtable extents; reviewed overlay: {stats['reviewed']} updated, "
        f"{stats['added']} added; source-declaration overlay: {stats['source']} updated)"
    )

    # 4. The stubs, from the same model + rows.
    write_stubs(
        repo_root,
        output_dir=gen_dir / "stubs",
        target=args.target,
        annotation_kind=args.annotation_kind,
        chunk_prefix=args.chunk_prefix,
        model=model,
        overlay_rows=rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
