# Tooling Architecture

## Package Layout

- `src/imperialism_re/cli.py`: single entrypoint (`uv run impk ...`), catalog dispatch, writer lock gate.
- `src/imperialism_re/command_catalog.yaml`: maintained command registry (name, module, mode, status, summary).
- `src/imperialism_re/commands/`: one module per command, each exposing `main()`.
- `src/imperialism_re/core/`: shared runtime/config/IO/typing helpers.

## Core Modules

- `core/config.py`: runtime defaults and env override resolution.
- `core/config.py`: runtime defaults, env override resolution, and shared project-root helpers (`default_project_root`, `resolve_project_root`).
- `core/runtime.py`: writer lock + pyghidra startup/project open primitives.
- `core/ghidra_session.py`: command-facing `open_program(...)` context manager.
- `core/catalog.py`: catalog loader + typed command specs.
- `core/csvio.py`: shared CSV read/write helpers.
- `core/typing_utils.py`: shared parse/type helpers (`parse_hex`, `parse_optional_hex`, `parse_int`, `parse_int_default`).

## Command Authoring Rules

- Add/maintain commands through `command_catalog.yaml`; every command module must expose `main()`.
- Use shared helpers from `imperialism_re.core.*`; avoid local duplicate parser/runtime helpers.
- Open Ghidra programs through `core.ghidra_session.open_program(...)` instead of inline `pyghidra.start(...)` / `program_context(...)` wiring.
- Resolve project roots through `core.config.default_project_root()` and `core.config.resolve_project_root(...)`.
- Standardize command root selection on `--project-root`; do not re-introduce positional `project_root` args.
- Keep command modules independent; do not import implementation helpers from other command modules.
- Use `argparse` for command argument parsing (avoid raw `sys.argv[...]` parsing).
- Keep command modules lane-focused (one operation family per module).
- Use CLI mode as source of truth:
  - `reader`: no writes
  - `writer`: mutates program state
  - `hybrid`: mixed behavior, still writer-locked

## Quality Guardrails

- `tests/test_tooling_smoke.py` validates:
  - catalog integrity and importability,
  - CLI help wiring for every catalog command,
  - writer-lock behavior,
  - absence of legacy Ghidra-console assumptions,
  - absence of local `parse_hex`/`parse_int` duplication in command modules,
  - absence of direct pyghidra session bootstrap in command modules,
  - absence of magic `Path(__file__).resolve().parents[3]` repo-root traversal in command modules,
  - absence of cross-command imports and raw `sys.argv[...]` parsing in command modules.
  - absence of positional `project_root` command arguments.
