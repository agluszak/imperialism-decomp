# Agent Guidelines (Imperialism RE)

## Primary Goal
Keep reverse-engineering momentum high by making small, safe, and save-persistent improvements in Ghidra.

## Ghidra Interaction Rules
- Default workflow: use direct local scripting with `pyghidra` via `.venv/bin/python`.
- Do not run analysis/rename work through MCP by default.
- Use MCP only as a fallback when explicitly needed and verified healthy.
- Keep one consistent execution path per pass (avoid mixing MCP and direct scripting in the same rename batch).
- Use `pyghidra` from `.venv/bin/python` for scripting.
- Start with explicit install dir:
  - `/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC`
- Open the project with resilient fallback logic (`open_project` first, then `PyGhidraProjectManager.openProject(...)` fallbacks).
- Use `pyghidra.program_context(project, "/Imperialism.exe")` for program access.
- Prefer one active writer session at a time to avoid project lock conflicts.
- Treat `GhidraMCP Module.manifest` warnings as non-blocking unless they prevent loading.

## Reusable PyGhidra Scripts (Use These First)
- Prefer script files in `new_scripts/` over ad-hoc inline snippets for repeated tasks.
- Use `.venv/bin/python` for all script runs.
- Standard class-extraction loop:
  1) scan candidate getter stubs,
  2) apply renames/labels from CSV,
  3) checkpoint progress counts.

### `new_scripts/scan_class_getters_fun6.py`
- Use when: starting a new address range and looking for low-risk class getter patterns.
- What it finds: `FUN_` 6-byte stubs with `MOV EAX,<desc>; RET`, plus nearby inferred `create/ctor/dtor`.
- Command:
  - `.venv/bin/python new_scripts/scan_class_getters_fun6.py <start_hex> <end_hex> [out_csv] [project_root]`
- Example:
  - `.venv/bin/python new_scripts/scan_class_getters_fun6.py 0x583000 0x594000 tmp_decomp/getters_583000_594000.csv`

### `new_scripts/apply_class_quads_from_csv.py`
- Use when: a scanned CSV (or hand-curated CSV) is ready for batch apply.
- What it does:
  - renames `Create/Get/Construct/Destruct` methods,
  - adds `g_pClassDescT*`, `g_szTypeNameT*`, and `g_vtblT*` labels,
  - adds short getter comments.
- Command:
  - `.venv/bin/python new_scripts/apply_class_quads_from_csv.py <csv_path> [project_root]`
- Example:
  - `.venv/bin/python new_scripts/apply_class_quads_from_csv.py tmp_decomp/getters_583000_594000.csv`

### `new_scripts/count_re_progress.py`
- Use when: reporting quick status after each pass (instead of rewriting one-off counting snippets).
- What it prints:
  - `total_functions`, `renamed_functions`, `default_fun_or_thunk_fun`,
  - `class_desc_count`, `vtbl_count`, `type_name_count`.
- Command:
  - `.venv/bin/python new_scripts/count_re_progress.py [project_root]`

### `new_scripts/generate_named_getter_neighbor_candidates.py`
- Use when: class getters are already renamed (`GetT*ClassNamePointer`) and you want a fresh, live list of adjacent unresolved `create/ctor/dtor` neighbors.
- What it finds:
  - candidate neighbor functions still `FUN_*` with lightweight ctor/dtor/create heuristics,
  - class descriptor/type-name addresses,
  - optional inferred vtable address (from ctor decomp pattern).
- Command:
  - `.venv/bin/python new_scripts/generate_named_getter_neighbor_candidates.py [out_csv] [project_root]`
- Example:
  - `.venv/bin/python new_scripts/generate_named_getter_neighbor_candidates.py tmp_decomp/named_getter_neighbor_candidates_current.csv`

### `new_scripts/apply_function_renames_csv.py`
- Use when: applying a curated non-class rename batch (game logic helpers, wrappers, tactical lane helpers) with optional comments.
- CSV columns:
  - required: `address,new_name`
  - optional: `comment`
- Command:
  - `.venv/bin/python new_scripts/apply_function_renames_csv.py <csv_path> [project_root]`
- Example:
  - `.venv/bin/python new_scripts/apply_function_renames_csv.py tmp_decomp/tactical_state_low_hanging_renames.csv`

### `new_scripts/generate_fun_callee_candidates.py`
- Use when: you already have a cluster of named caller functions and want unresolved `FUN_*` callees reachable from that cluster.
- Input:
  - caller name regex
- Output CSV:
  - `callee_addr,callee_name,total_calls,unique_callers,caller_names`
- Command:
  - `.venv/bin/python new_scripts/generate_fun_callee_candidates.py <caller_regex> [out_csv] [project_root]`
- Example:
  - `.venv/bin/python new_scripts/generate_fun_callee_candidates.py \"Tactical|ArmyPlayer|NavyPlayer\" tmp_decomp/tactical_fun_callee_candidates.csv`

### `new_scripts/generate_fun_caller_candidates.py`
- Use when: you have a set of named callee functions (matched by regex) and want unresolved `FUN_*` callers that invoke them.
- Input:
  - callee name regex
- Output CSV:
  - `caller_addr,caller_name,total_hits,unique_callees,callee_names`
- Command:
  - `.venv/bin/python new_scripts/generate_fun_caller_candidates.py <callee_regex> [out_csv] [project_root]`
- Example:
  - `.venv/bin/python new_scripts/generate_fun_caller_candidates.py \"TTradeMgr|TDiplomacyMgr\" tmp_decomp/trade_diplomacy_fun_caller_candidates.csv`

### Practical Rules
- If scan output is empty in a range (`rows=0`), move to a new range instead of forcing deeper work there.
- Keep CSV-driven batches coherent (single region/family) to simplify rollback reasoning.
- After every apply batch:
  - run `count_re_progress.py`,
  - save findings + TODO in `agent_1.md`.

## Editing Discipline in Ghidra
- Wrap changes in a transaction:
  - `tx = program.startTransaction("...")`
  - `program.endTransaction(tx, True)` on success.
- Always persist edits with `program.save("reason", monitor)` after each batch.
- Keep rename batches small and coherent (single cluster / single intent).
- Rename only when behavior is directly supported by decomp/callers/constants.
- Avoid speculative semantic names; prefer behavior-based names if uncertain.
- When renaming a core function, also rename easy thunk wrappers that directly forward to it.
- Add short function comments for non-obvious behavior (especially index/stride/state semantics).

## Analysis Workflow
- Start from one anchor function and inspect:
  - direct callers,
  - direct callees,
  - constants,
  - nearby thunk islands.
- Prioritize low-hanging game-logic over UI plumbing unless asked otherwise.
- If stuck on one function, move to adjacent easy wins and come back later.

## Signature and Variable Hygiene
- Update function signatures when argument roles are clear and stable.
- Rename local variables only when it improves readability materially.
- Do not force full retyping; do incremental, high-confidence type improvements.

## Documentation Sync
- Update `agent_1.md` after each meaningful pass:
  - what was renamed,
  - why it is safe,
  - what remains in TODO.
- Keep Neo4j updates for high-level discoveries only, not every low-level rename.
- Neo4j stores high-level Imperialism domain knowledge and resource mappings (e.g., bitmaps, strings, table IDs).
- If Neo4j is needed for context but currently unavailable/down, ask the user for guidance or required context instead of blocking.

## Safety Constraints
- Never revert unrelated user changes.
- Do not run destructive git commands.
- If unexpected workspace mutations appear, stop and ask before proceeding.
