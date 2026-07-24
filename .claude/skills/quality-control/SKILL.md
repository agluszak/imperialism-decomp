---
name: quality-control
description: Build, measure, and gate the Imperialism decomp — rebuild with Docker MSVC500, run reccmp detect/compare/stats, compare aggregate stats against baseline, enforce the raw-vtable gate, format C++, and diagnose reccmp pairing failures. Use when building, checking similarity scores, guarding against regressions, or debugging why a function won't pair.
---

# Quality control

Build, measurement, gates, and regression diagnosis. Obey the Command Policy in
`AGENTS.md`: use `just` targets, not raw `docker`/`uv run reccmp-*`.

## Build & measure

- `just tooling-check` — verify the toolchain surface is present.
- `just build` — full pipeline: `vtable-gate` → Docker MSVC500
  build.
- `just detect` — re-run reccmp recompiled detection (do this after every rebuild).
- `just compare 0xADDR` — targeted verbose compare of one function (the acceptance
  gate for a touched body). With no address, runs a full compare.
- **Batch mode (one PDB parse for many functions — use this instead of looping
  single compares):** `just compare 0xA 0xB 0xC ...` scores several addresses at
  once; `just compare --file src/game/X.cpp` scores every `// FUNCTION:` marker in
  a file; `just compare-class X` is shorthand for the latter. All three run reccmp
  once with an address-filtered JSON report; unrelated functions are not
  disassembled or verified.
- `just triage 0xADDR` (or `--file src/game/X.cpp`) — **run this before reading a raw
  compare diff by eye.** Multiple addresses are analyzed in one fresh, filtered
  reccmp process. Targeted analysis loads conservatively resolved PDB object modules
  and reuses the fingerprinted `.reccmp-cache` beside the PDB. Parsed PDB, markers,
  and prepared entity state may be cached; semantic proof results never are. The
  cache invalidates when relevant binaries, PDB, source/data, config, or analyzer
  code changes; use reccmp's `--no-cache` only for cache-independent diagnosis. It
  consumes `entity["comparison"]` from reccmp's report;
  it does not classify rendered instruction text. `exact` needs no work,
  `effective` lists the proof transformations that are safe to ignore, `mismatch`
  reports the first trusted observable divergence with structured operand facts,
  and `inconclusive` explicitly says reccmp did not prove the source wrong.
- `just stackcmp-triage` — batch `reccmp-stackcmp` over the near-match score range
  and rank stack-layout suspects (each run re-parses the PDB, so it caps at
  `--limit`, default 12).
- `just stats` — aggregate progress compared against the committed baseline. It reports
  improved and worsened metrics separately.
- `just stats-baseline-update` — update the committed aggregate baseline after accepting the
  current stats snapshot. Per-function `compare` remains the real gate for touched
  bodies.
- `just install-reccmp-merge-driver` — one-time local Git setup. When either generated
  progress baseline conflicts during a merge/rebase/cherry-pick, the driver preserves
  a valid side and tracked hooks rebuild and regenerate both files after integration.
  The result is deliberately unstaged: review it before committing. Set
  `IMPERIALISM_SKIP_RECCMP_BASELINE_REFRESH=1` to defer the automatic rebuild.

## Pre-commit sequence

```sh
just precommit      # build + gates + tooling tests + stats in one command
just stats-baseline-update   # if stats are acceptable; commit baseline with source
```

See `.cursor/rules/commit-workflow.mdc` for regression thresholds and failure handling.

## Export-sync sequence (run whenever markers/ownership change)

```sh
just generate         # regenerates build inputs (source index + stubs) — also runs inside `just build`
just build
```

## Gates & formatting

- `just gates` — run all mechanical source-policy gates (the pre-commit check):
  `vtable-gate`, `antipattern-gate`, `marker-gate`,
  `vtable-annotation-gate`, `vtable-collision-gate`,
  `synthetic-gate`, `decomplint`, plus the ratchet gates `datacmp-gate`,
  `stub-count-gate`, `class-size-gate`, and `noop-gate`. **All must pass before
  committing.**
- **Ratchet gates** (each has a `just <gate>-update` baseline target; update only
  after reviewing the delta, and commit the baseline with the change):
  - `datacmp-gate` — per-variable reccmp-datacmp fingerprints
    (`config/datacmp_baseline.csv`) may not regress; `just datacmp` stays the raw
    report.
  - `stub-count-gate` — the autogen stub count (`src/autogen/stubs/_manifest.json`)
    may not rise. A rise is the un-claiming tell (see the
    `sync-pipeline` skill): real marker-less owners got re-stubbed.
  - `class-size-gate` — `ASSERT_SIZE` vs the RTTI oracle, strict; known mismatches
    live in `config/class_size_allowlist.txt`, each citing a bead.
  - `noop-gate` — empty (`{}` / `(void)arg;`-only) bodies may not grow per file
    (`config/empty_body_baseline.csv`); an intentionally-empty body needs a
    `// FUNCTION` marker or `// NOOP: verified empty in original 0xADDR`, and a
    NOOP annotation contradicted by the original size always fails.
    `just noop-audit [--kind empty_but_big]` lists the current findings — it is
    also a port-target menu (empty bodies whose originals are big).
- `just vtable-gate` — baseline-free **hard ban**: any raw `vftable[...]` / `VCall_*` /
  Fn-typedef-cast pattern fails. Zero occurrences allowed; there is no `-update` target.
- `just antipattern-gate` — baseline-free **hard ban** on the mechanically-checkable
  real-C++-construction Hard Rules (no inline asm, no `new (this)`, no manual vptr writes,
  no `__thiscall` reinterpret_cast, no operator-new factories, no temporary bridge-helper
  names, no raw `this+offset` casts). Any hit is a source defect to fix, never to bless;
  there is no `-update` target.
- `just marker-gate` — enforces marker Hard Rules 3 (marker immediately precedes the
  declaration) and 4 (one owned implementation per address across manual files + stubs).
- `just format` / `just format-check <paths>` — clang-format C++. The tree is not fully
  formatted, so run `format-check` on the files you touched, not whole-tree (it is not
  part of `just gates`).
- `just normalize-markers` — reformat `// FUNCTION` / reccmp markers (cosmetic;
  `marker-gate` is the policy check).

## Never revert architecture to pass a gate (fix forward)

When `just gates`, `just vtable`, `just build`, or a pre-commit check fails **after**
you have promoted real C++ shape (typed fields, real methods, `new T()`, typed
singleton globals), **never undo that work to make verification pass.** Regressing from
real methods back to `extern undefined4` + `reinterpret_cast` at the callsite is
strictly worse than a failing gate — it is a source-model corruption (construction Hard
Rule 11). This is the `AGENTS.md` "gate-chasing guardrail" in operational form.

The failure mode to avoid: port real shape → a gate fails → revert the real shape to
stubs so the gate passes. **That revert is forbidden.** Fix forward, in order:

1. **Build/link** — missing symbol: promote/own the callee as a real method, or use a
   genuine LIBRARY symbol (`operator new` at `0x606f73`, not a fake
   `AllocateWithFallbackHandler` stub). Wrong owner: fix the marker; stubs regenerate on
   the next build.
2. **Duplicate marker** — one address, one owner; move `// FUNCTION:` to the class that
   owns the method, sync ownership, regen stubs. Do not delete the manual method.
3. **`just vtable Class`** — the first `new T()` in manual code can expose a pre-existing
   class-model gap. Fix slot ownership / imports / missing overrides on that class; do
   **not** stop constructing the class and do **not** re-stub callsites.
4. **`antipattern-gate`** — prefer `new T()` over explicit `operator new` + placement;
   prefer real inheritance over bridge thunks. Do not replace `new T()` with stub dispatch.

If none of these resolves the gate **without** architectural regression, **stop and
report** what failed, what you tried, and what class-model work remains. A blocked
commit with correct source beats a passing commit with reverted stubs.

**Callee classification — pick once, do not flip-flop:**

| Evidence | Correct model | Forbidden rollback |
|----------|---------------|--------------------|
| `mov ecx, …` / callee uses `[ecx+off]` | Real `__thiscall` method on owning class; `obj->Method()` | `reinterpret_cast` to `__thiscall*` on `undefined4` stub |
| Vtable dispatch | Real `virtual` on recovered class | Raw `vftable[i]` or `VCall_*` facade |
| `0x606f73` / `AllocateWithFallbackHandler` in listing | `new T()` (MFC `operator new` LIBRARY in `mfc_heap_library.cpp`) | `new char[n]` + stub ctor cast |
| `// LIBRARY:` in repo | Link against MFC; no stub definition | Add a fake `undefined4` stub |
| Genuine `__cdecl` free function, no `this` | Port the real callee when feasible; the legacy `extern undefined4` + typed-cast-at-callsite form is a bridge being retired, not a porting approach | — |

The legacy typedef-cast form applies **only** to genuine free-function thunks. It does
not permit re-stubbing a callee you already verified is `__thiscall` on a recoverable
class because a gate failed. Promotion is one-way: once a callsite uses
`g_pX->Method(...)` or `new TNetMgr()`, do not put the free-function stub or fake
calling-convention cast back to unblock a commit.

## reccmp specifics

reccmp is installed from a full, immutable fork commit in `pyproject.toml` (no local
checkout needed unless editing reccmp itself). After advancing the fork, update the
full SHA and run `uv lock --refresh-package reccmp`; do not commit a local-file Git
override. Verify the lock resolves the pushed remote commit. The `just` targets wrap it:

- detection: `reccmp-project detect --what recompiled`
- compare: `reccmp-reccmp --target IMPERIALISM [--verbose 0xADDR]`

Notes: re-run `detect` after each rebuild; tiny wrappers can be folded/aliased by the
linker, so a targeted compare may map to an unexpected symbol; keep `reccmp-user.yml`
local/gitignored and commit only `reccmp-project.yml`.

### Oversized-vtable diagnostics

`just vtable [Class]` reports the evidence behind every "recomp vtable is larger"
warning instead of presenting it as a generic class-size defect:

- `slots candidate=N` is the pointer count reccmp would compare; `orig_bound=N` is
  the tightest declared-size or next-entity metadata bound.
- `first_null=N` is the first null pointer in the original across the full candidate
  extent. `None` means the original pointers continue through that extent;
  `unavailable` means the binary range could not be read completely.
- `trigger=declared_size`, `boundary`, or `null` lists every reason the candidate is
  considered oversized. The `bytes` line preserves all raw `size`, `max_size`, and
  `any` values for metadata debugging.
- For `boundary`, the final line names the original entity at the limiting address.
  A data entity inside a non-null pointer run usually means stale/interior
  `original_entities.csv` metadata. A separately named dispatch table at the exact
  boundary may be a genuine split that the recomp class model merged. A `null`
  trigger is direct evidence of the original vtable tail and usually points to
  inheritance or an extra override.

These diagnostics are emitted on both cold analysis and prepared-cache hits. Use
the named boundary plus `just ghidra vtable-dump`/`just ghidra read-data` before
changing inheritance or deleting an annotation.

### Structured semantic diagnosis

The JSON report's `comparison` object is authoritative; the legacy `effective`
boolean and old report schema are unsupported. It contains:

- `status`: `exact`, `effective`, `mismatch`, or `inconclusive`;
- `effective_reasons`: deterministically ordered proof reasons, only for
  `effective` (`register_allocation`, `frame_slot_layout`,
  `callee_save_substitution`, `instruction_reorder`, `commutative_order`,
  `condition_inversion`, `dead_operation`, `padding`);
- `difference`: the first trusted divergence, only for `mismatch`, with kind
  (`call_target`, `call_argument`, `memory_address`, `memory_value`,
  `immediate_value`, `branch_condition`, `branch_target`, `return_value`,
  `preserved_state`, `symbol_resolution`) plus original/recompiled instruction
  indices, addresses, and primitive facts;
- `inconclusive_reason` and optional `inconclusive_location`, only for
  `inconclusive` (`unsupported_instruction`, `unsupported_control_flow`,
  `alignment_failure`, `missing_metadata`, `analysis_limit`).

Result precedence is `exact` → any complete `effective` proof → a concrete mismatch
from trusted CFG/lockstep pairing → `inconclusive`. A speculative alignment failure
cannot override a proof or manufacture an actionable mismatch. Raw similarity remains
useful for progress and local context, but it is not semantic classification: inspect
the formatted diff only after triage reports `mismatch`.

`commutative_order` also covers reassociated integer-add reductions when no
intermediate flags are consumed. If triage proves such a reduction effective, retain
the natural typed source expression; do not permute operands or split statements to
chase VC5's chosen load order.

## Known reccmp failure modes

1. **`Failed to find a match at address 0x...`**
   - Check `// FUNCTION` marker placement (must be immediately above the declaration,
     no comment/blank line between).
   - Check for duplicate address ownership (one impl per address; no duplicate
     `// FUNCTION` across manual files and stubs).
   - Re-run `just build` + `just detect`.
2. **`Dropped duplicate address ...`** — the same address is still annotated in a stub
   shard or another manual file.
3. **Compare name looks like a sentence/comment** — a comment line sits between the
   marker and the declaration.
4. **Build breaks on `__thiscall` in a free typedef** — the callee is a class method:
   declare it as a real method on the owning class and call `obj->Method(args)`.
   Never put `__thiscall` casts on free functions/function pointers. Only when no
   class can yet be modeled is a `__fastcall` bridge an acceptable last resort (see
   the AGENTS.md calling-convention guardrail) — and it belongs outside primary
   method bodies.
5. **`InvalidVirtualAddressError: …Imperialism.exe : 0x…`** (reccmp crashes hard
   during compare/stats) — the exe and PDB are out of sync: the PDB references code
   past the current exe. Almost always a wrong-flags build. Rebuild with `just build`
   (real flags: `RelWithDebInfo`, `IMPERIALISM_LINK_MFC=ON`, `/Oy-,/Ob1`) — a good
   build is ~742 KB exe + a fresh ~4.8 MB pdb, not a ~120 KB exe with a stale pdb.
6. **`Target IMPERIALISM is missing data: recompiled_path,recompiled_pdb`** — the
   `build-msvc500/reccmp-build.yml` is stale/missing (e.g. after `rm -rf build-msvc500/`).
   Run `just detect` to repopulate it, then re-run the reccmp tool.
7. **`just vtable` shows *all* (or hundreds of) vtables "not matching", each failing at
   the same slot 0x04** — the scalar-deleting-destructor names in `config/original_entities.csv`
   drifted from the form the recomp PDB emits. They must read
   `` <Class>::`scalar deleting destructor' `` (backticks, spaces) to pair; a regen can
   rewrite them to `'scalar_deleting_destructor'` or `Destruct<Class>AndMaybeFree`, which
   never pair. Diff `config/original_entities.csv` against the last-good commit and restore the
   scalar-dtor name field per address (commit 22efcd3c restored the whole file from its
   parent after the 5b715e03 regen broke 272/272 vtables and dropped 369 aligned funcs).
   The same regen-induced name drift also shows up as a large `just stats` alignment drop.
8. **Regressions right after a resync** (mass score drops around `thunk_*` names, one
   function 100→0, unresolved `thunk_*` externals at link, +N original-only globals) —
   these are symbols.csv/ownership pipeline symptoms, not build problems. See the
   **`sync-pipeline` skill** ("Resync failure → fix") for the taxonomy and fixes.

## `just ctor-placement-gate`

Ratchet gate: fails on any NEW constructor defined out-of-line in a .cpp without a
`// FUNCTION` / `// SYNTHETIC` marker. No marker means no address in the original, so the
compiler always absorbed that body into its callers; an out-of-line definition cannot be
inlined across TUs and pessimizes every subclass ctor and `CreateObject` into a `CALL`.

Baseline `config/baselines/ctor_placement_baseline.txt` (95 entries) is a backlog to
shrink, tracked in bd nwdn. Refresh only after genuinely resolving entries, with
`just ctor-placement-gate-update` (requires `ALLOW_POLICY_BASELINE_UPDATE=1`).

**Never add a new entry to the baseline to silence the gate.** Read the caller's listing
first. The rule is one question — does the original have a standalone body for this ctor?
No address means in-class is free; an existing address means it is a trade, because our
one-class-per-file layout cannot reproduce `/Ob1`'s "standalone body + same-TU inlined
users" shape. Full reasoning in the `ctors-dtors-eh` skill and `docs/toolchain.md`.
