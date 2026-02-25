# Agent Notes

Project-specific execution rules are defined in:

- `INSTRUCTIONS.md`

Any agent working in this repository must follow `INSTRUCTIONS.md` for naming, export-sync, and source-of-truth policy.

## Mandatory Decomp Loop

Run this as a continuous loop during active matching work:

1. Pick one target function (or a tightly-coupled neighbor pair).
2. Do a `shape pass` first:
   - preserve call order, branching shape, and fail-and-continue behavior from Ghidra.
   - prefer real virtual-call wrappers (no inline asm, no raw address+offset calls).
3. Do a `data pass`:
   - align local types (`short`/`int`), clamp behavior, and float/int conversion order.
4. Rebuild with Docker MSVC500 and run targeted `reccmp --verbose` only for touched functions.
5. Verify no regressions on adjacent functions.
6. Record concrete lessons/heuristics in `INSTRUCTIONS.md` (`Similarity Improvement Notes`).
7. Update docs:
   - `docs/control_plane.md` with current strategy + checkpoints.
   - `docs/worklog.md` with timestamped changes, commands, and score deltas.
8. Repeat immediately with the next highest-impact mismatch.

## Docs To Keep In Sync

- `docs/control_plane.md`: active strategy, baseline/checkpoint metrics, canonical commands.
- `docs/worklog.md`: chronological execution log and outcome deltas.
- `docs/toolchain.md`: compiler/toolchain forensics and decisions.
- `docs/reccmp_fork.md`: local fork integration and command usage.

## Command Policy

Use `just` targets by default for project workflows.

1. Prefer:
   - `just build`
   - `just detect`
   - `just stats`
   - `just compare <addr>`
   - `just sync-ownership`
   - `just promote <target> --address 0x...`
2. Do not run raw `docker`, `uv run reccmp-*`, or direct workflow scripts when an equivalent `just` target exists.
3. Use direct commands only when there is no `just` target for the required action; if so, keep it minimal and add/update a `just` target afterward.
