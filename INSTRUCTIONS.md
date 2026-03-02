# Imperialism Decomp Instructions

## Hard Rules

1. No inline assembly.
2. Use `just` targets for normal workflow (`build`, `detect`, `compare`, `stats`, `promote`, `sync-ownership`, `regen-stubs`).
3. `// FUNCTION: IMPERIALISM 0x...` must be immediately followed by the function declaration.
4. Do not place any other comment or blank line between `// FUNCTION` and the declaration.
5. One owned implementation per address in manual source.
6. No duplicate `// FUNCTION` for the same address across manual files and stubs.
7. If you edit markers/ownership, run:
   1. `just sync-ownership`
   2. `just regen-stubs`
   3. `just build`
8. Keep naming from Ghidra unless there is a concrete semantic reason to rename.
9. Do not rename for style-only reasons.
10. Keep class-owned functions in `src/game/<ClassName>.cpp`.
11. Keep non-class/global trade code in `src/game/trade_screen.cpp`.
12. For free-function bridges in this toolchain, prefer `__fastcall`; avoid `__thiscall` casts in free function pointer typedefs.

## Promotion Loop

1. Pick one function or a tight neighbor pair.
2. Promote with `just promote ...` (or `just promote-range ...`).
3. Make compile-safe C++ first; do not micro-tune immediately.
4. Run ownership/stub sync.
5. Run `just build`, `just detect`, `just compare 0xADDR`.
6. If score moves, keep it and move on; if stuck, move to next function.

## Known reccmp Failure Modes

1. `Failed to find a match at address 0x...`:
   1. Check marker placement (rule #3/#4).
   2. Check duplicate address ownership (rule #5/#6).
   3. Run `just sync-ownership` + `just regen-stubs` + `just detect`.
2. `Dropped duplicate address ...`:
   1. Same address is still annotated in a stub shard or another manual file.
3. Compare name looks like a sentence/comment:
   1. A comment line is between marker and declaration.
4. Build breaks on `__thiscall` in free typedef:
   1. Replace with `__fastcall` bridge shape.

## Logging Policy

1. Keep execution details in `docs/worklog.md`.
2. Update `docs/control_plane.md` only when strategy changes.
3. Do not duplicate the same long status in multiple places.
