# Maintained Tooling Commands

Canonical invocation:

```bash
uv run impk <command> [args...]
```

Project setup:

```bash
uv sync --dev
```

List commands:

```bash
uv run impk list
```

Architecture and module conventions: `docs/architecture.md`.

## Command Families

- Wave orchestration: `run_wave_bundle`, `run_unresolved_wave`, `run_class_harmonization_wave`
- Quality gates: `find_named_functions_with_generic_callees`, `list_unresolved_functions_in_range`, `count_re_progress`
- Apply/write lanes: `apply_*`, `create_*`, `move_functions_to_global_namespace_csv`, `rename_struct_fields`, `functionize_*`, `recover_*`
- Read/generate lanes: `list_*`, `find_*`, `dump_*`, `inventory_*`, `derive_*`, `generate_*`, `scan_hidden_decomp_params`, `build_redecomp_wave_from_ownership`

## Runtime Configuration

Commands read these environment variables:

- `IMPK_GHIDRA_DIR` (default: local Ghidra 12.0.2 path)
- `IMPK_PROJECT_ROOT` (default: repository root)
- `IMPK_PROJECT_NAME` (default: `imperialism-decomp`)
- `IMPK_PROGRAM_PATH` (default: `/Imperialism.exe`)

## Writer Safety

Writer/hybrid commands are serialized via `.imperialism_re_writer.lock` in project root.
If another writer is active, command dispatch fails fast.
