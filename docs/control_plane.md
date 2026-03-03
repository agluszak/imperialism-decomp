# Imperialism Decomp Control Plane

Last updated: 2026-03-03 (late PM)

## Purpose

This file tracks:

1. Current working strategy.
2. Baseline metrics/checkpoints.
3. Canonical command loop.

## Strategy (Current)

1. Keep Ghidra export artifacts as the source of truth for addresses/names.
2. Keep manual code in `src/game/`; keep generated code in autogen paths only.
3. Prioritize conversion of high-impact non-trivial function bodies (not tiny thunk wrappers).
4. Preserve marker/ownership hygiene every iteration:
   1. `just sync-ownership`
   2. `just regen-stubs`
5. Use canary compares to catch local regressions before broad tuning.
6. Track globals and non-function entities in stats (not only functions).
7. Keep vcall facades generated as direct slot-call wrappers (avoid extra runtime-helper call layers in hot paths).

## Canonical Commands

Environment/bootstrap:

1. `just tooling-check`
2. `just docker-build` (when image needs rebuild)
3. `just sync-ghidra`

Iteration loop:

1. `just promote ...`
2. Compile-fix only for the promoted body.
3. `just sync-ownership`
4. `just regen-stubs`
5. `just build`
6. `just detect`
7. `just compare 0xADDR`
8. `just compare-canaries`
9. `just stats`

Maintenance:

1. `just inventory`
2. `just generate-ignores`
3. `just normalize-markers`
4. `just vtable-gate`

## Baseline Snapshot

Baseline reference before this control-plane trim:

1. Aligned functions: `91`
2. Average similarity: `2.92%`
3. Focus area: `TGreatPower` large-body conversion and cleanup

## Active Constraints

1. No inline assembly.
2. No raw address+offset call sites in gameplay code.
3. No comment/blank line between `// FUNCTION` marker and declaration.
4. Use generated vcall facades instead of local vtable typedef/cast blocks.
5. Prefer reusable tooling over one-off scripts; wire it through `just` when stable.
6. Keep strict layout asserts only on proven-stable `TGreatPower` core offsets; keep tail offsets as non-fatal probes until tail stabilization.
