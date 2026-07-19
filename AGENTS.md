# Imperialism Decomp — Agent Guide

Decompilation workspace for the Windows game **Imperialism (1997)**. We reverse the
binary into matching C++, rebuild it with the original MSVC500 toolchain in
Docker/Wine, and track per-function similarity with `reccmp`. The goal is a
byte-faithful, reproducible-in-git rebuild.

This file is the contract: the invariants below hold for all work. Per-workflow and
per-topic detail lives in **skills** (`.claude/skills/`). **Loading the matching
skill is part of the job, not optional**: before porting a function, load the
topical skills matching its dominant traits (see the table below); before any
workflow task, load its workflow skill. The old monolithic heuristics file is gone —
its notes live inside these skills, so skipping the skill means working blind.

## The workflow entrypoints (use these, not memory)

Every porting/fixing task goes through three stateful commands — they execute the
correct process so you never have to reconstruct it:

```sh
just agent-start port 0xADDR   # investigation front door: refuses stale bases,
                               # already-implemented targets, and addresses claimed
                               # by another live branch (refs/agent-claims/*); runs
                               # tooling-check, func-status, ghidra-portprep, the
                               # initial compare, library-identify; writes
                               # build-msvc500/agent-task.json
just advice 0xADDR             # the 5-10 most relevant active rules for this target
                               # (from config/agent_rules.yml); `just advice --diff`
                               # selects by the current working diff instead
just agent-check               # diff-aware verification: regenerates build inputs
                               # (hard error on hand-edited generated files),
                               # format-check on touched paths, build, detect,
                               # compare+triage of every touched address, gates, tests
just agent-finish              # PR title + body from the receipt (build-msvc500/pr-body.md)
just agent-release             # after the work lands: free the claim refs (24h TTL otherwise)
```

The receipt is guidance, not proof — CI recomputes the checks. Policy-baseline
updates (`antipattern-gate-update`, `stub-count-gate-update`, and friends) are
exceptions to architecture rules and refuse to run without
`ALLOW_POLICY_BASELINE_UPDATE=1`, which requires an explicit human approval —
never set it to make a red gate go away (see the gate-chasing guardrail).

## Workflow skills (how to do each kind of task)

- **`decomp-loop`** — the core function-porting loop (seed → shape pass → data
  pass → build → compare). Its `heuristics.md` keeps only loop-process notes and the
  legacy note-number resolution table.
- **`ghidra`** — inspect `Imperialism.exe` via pyghidra (listing, decompile, vtable
  dump, cdecl/thiscall scan) and the interactive function-documentation methodology.
- **`quality-control`** — build, reccmp detect/compare/stats, gates,
  formatting, and reccmp pairing-failure diagnosis.
- **`sync-pipeline`** — the derived-artifact pipeline: the raw entity inventory, function
  ownership, generated stubs, `just generate`/`ghidra-apply-source`, and the
  resync failure→fix taxonomy (junk thunk rows, type flips, size clamps).
- **`class-recovery`** — class/vtable reconstruction, slice/class discovery,
  Mac-evidence oracle use, and real-virtual dispatch on recovered classes.
- **`vtable-matching`** — drive `just vtable <Class>` to 100%: read the reccmp vtable
  diff and fix per-slot mismatches (inherited-base, scalar-deleting-dtor, missing
  override, stub-in-slot, imported-thunk). Separate from `class-recovery`, which
  reconstructs an unknown layout/inheritance in the first place.
- **`run-debug`** — run the recomp under Wine, scripted winedbg sessions, and the
  capture-by-window-ID screenshot recipe for visual verification.

## Topical skills (load by what the target function contains)

Match a function's traits to skills and load EVERY one that applies **before**
porting or diagnosing it:

| The function/target has… | Load |
| --- | --- |
| any callee to declare, an ECX load before a CALL, a Ghidra `__cdecl` label, a `ret N` question, a suspect receiver/attribution | **`calling-conventions`** |
| CString/text/format/assert strings, string-pool literals, `CDumpContext` | **`string-handling`** |
| an EH prologue (`push -1`/`__ehhandler`), non-POD locals, `new`-expressions, ctor/dtor work, scalar deleting dtors | **`ctors-dtors-eh`** |
| float/double math, FPU diff lines, unexplained +8 frame bytes | **`fp-matching`** |
| loop/branch/switch shape mismatches, flag bytes, `sete`, magic-number division, sign-extension noise | **`codegen-shapes`** |
| unlabeled `.data`/`.rdata` reads, new globals/structs, field-width questions | **`data-modeling`** |
| size ≥ ~500B, a giant switch, or any "this is too complex" feeling | **`big-functions`** |
| MFC collection-shaped vtables/fields/internals | **`mfc-collections`** |
| unknown class layout/inheritance to reconstruct | **`class-recovery`** |
| a below-100% vtable or wrong-slot diff | **`vtable-matching`** |

Two standing behavioral rules the topical skills exist to enforce:

1. **No function is "too complex" to port.** Strings, EH scaffolding, size, and FP
   density are never reasons to postpone, stub, approximate, or hand back a target —
   each has a skill that turns it into mechanical transcription. Deferred/TODO bodies
   are not an outcome; a structurally-faithful port at 40–60% is.
2. **Ground truth comes from the Ghidra tooling, not from memory or the decompile.**
   Before porting: `just ghidra-listing 0xADDR` for the real instructions, resolve
   every ILT thunk to its target, verify conventions per `calling-conventions`, and
   read constants/strings from the binary (`just string-oracle`, datacmp). If you
   have not run the listing, you do not know what the function does.

## IMPORTANT
- Game is compiled with MSVC500 (Visual C++ 5.0), which is an old compiler. DO NOT USE modern C++ features or syntax.
- code coming from MFC/other Windows libraries MUST NOT be modelled/ported. Use // LIBRARY annotations for it
- ILT thunks must not be used at all - they should be completely ignored. Use the target methods instead.

## Docs (the durable record)

- Git history — clear commit messages are the durable execution record for what
  changed, how it was verified, and any score deltas.
- `docs/workflows.md` — the canonical command playbooks (fresh-worktree bootstrap,
  daily port loop, marker/ownership edits, full Ghidra DB resync). Start here when
  unsure which `just` target to run; `just --list` groups every target and flags
  mutating ones. In a fresh worktree, run its §0 bootstrap first (`.env`,
  `reccmp-user.yml`, `just restore-project`) — gitignored machine state does not
  follow the git tree.
- `docs/toolchain.md` — compiler/linker forensics and reproduction decisions.
- `docs/reference/` — layout/contract and game-domain references (struct layouts,
  function/entry-chain map, bitmap IDs, tech unlocks).

## Environment & tooling

- **Python tooling runs through `uv`.** Use the `just` targets (preferred) or
  `uv run python -m tools...`; never bare `python`. `.env` holds only machine-specific
  paths (`GHIDRA_INSTALL_DIR`, `ORIGINAL_BINARY`, optional `MACOS_IMPERIALISM_DUMP`);
  see `.env.example`. Everything else is a constant in the `justfile`.
- **MSVC/MFC headers are available locally for reference.** Populate the gitignored
  mirror with `just vendor-msvc500-headers`, then inspect
  `vendor/msvc500/headers/{include,mfc/include,atl/include}` instead of guessing MFC
  signatures or collection layouts.
- **Ghidra is the ground-truth evidence source.** Read the disassembly before trusting
  a decompile or a name; prefer it over objdump. The full inspect-command catalog
  (listing, xrefs, func-sig, field-xrefs, string-oracle, cdecl/thiscall scan, decompile,
  persistent daemon) lives in the `ghidra` skill and `just --list`. The vendored project
  (`vendor/ghidra`) is authoritative; the tools verify the installed Ghidra matches
  `ghidra.toml` and fail fast on a mismatch.
- **Ghidra naming and calling conventions are provisional** (see Hard Rule 6 and the
  MSVC500 calling-convention guardrail): treat every name and
  `__cdecl`/`__fastcall`/`__thiscall` label as a hypothesis to verify against the
  assembly, never as ground truth.

### reccmp verification & comparison commands

Each wraps a `uv run reccmp-*` tool via a `just` target (Hard Rule 2 — prefer the
target). They need a built binary + reccmp DB. Details in the `quality-control` skill.

- `just precommit` — the whole pre-commit sequence in one command: `build` +
  `gates` + `test` (tooling unit tests) + `stats`.
- `just gates` — the mechanical source-policy gates: `decomplint` plus the ratchet
  gates (`datacmp-gate`, `stub-count-gate`, `class-size-gate`, `noop-gate`), each
  with a `just <gate>-update` baseline target.
- `just triage 0xADDR` / `just triage --file src/game/X.cpp` — classify every
  mismatched diff line of a below-100% function into actionable buckets with the
  standard next action per bucket. Run this before reading a raw `just compare`
  diff by eye.
- `just vtable [Name]` (vtable correctness), `just datacmp [-a]` (global data values),
  `just roadmap` (symbol locations of functions/vtables/data), `just stackcmp 0xADDR`
  + `just stackcmp-triage` (stack layout of near-matching functions).

## Hard Rules

1. No inline assembly. (enforced by `just antipattern-gate`)
2. Use `just` targets for normal workflow (`tooling-check`, `build`, `detect`,
   `compare`, `stats`, `generate`). Do not run raw
   `docker` or `uv run reccmp-*` when a `just` target exists; if no target exists,
   keep the direct command minimal and add a target afterward.
3. `// FUNCTION: IMPERIALISM 0x...` must be immediately followed by the function
   declaration — no comment or blank line between them. (enforced by `just marker-gate`)
4. One owned implementation per address in manual source; no duplicate `// FUNCTION`
   for the same address across manual files and stubs. (enforced by `just marker-gate`)
5. After editing markers/ownership, just run `just build` — it regenerates the build
   inputs (source index + stubs) from current markers automatically — and `just gates`
   before committing (raw-vtable + construction anti-pattern + marker-hygiene gates;
   run `just format-check <touched paths>` separately on files you edited).
6. Treat Ghidra class/method/field names as **provisional** —
   they may be auto-generated placeholders, even entirely random. reccmp pairs by the
   `// FUNCTION:` address marker, not by name, so drive matching and field naming from
   observed behavior in the disassembly, and keep tentative names hedged.
7. Keep class-owned functions in `src/game/<ClassName>.cpp`. **Every file under
   `include/game/` and `src/game/` is manually owned source** — author and edit its
   declarations and bodies by hand, then verify with `just build` / `just vtable` /
   `just gates`. There are no tool-owned source trees anymore: generated inputs
   (stub TUs, the source index) live in the build directory and Ghidra reference
   exports go to build evidence — only files carrying an `AUTO-GENERATED by tools/…`
   banner are tool output; do not hand-edit those. The
   retired `recover-class` source generator is gone: there are no "generated
   declaration" blocks or "do not hand-edit" boundaries inside manual headers (a
   `just generated-marker-gate` rejects them if they reappear). Read-only Ghidra
   extractors (`just class-vtable-dump`, `just vtable-abi-audit`, discovery targets)
   may inspect manual source and push its names into the Ghidra DB, but must never
   rewrite a declaration, body, symbol prototype, or ownership row.
8. Promote repeated `this + offset` / `reinterpret_cast` access that maps to a stable
   class region into a typed class field (or typed view struct) instead of cast-helper
   indirection.
9. For vtable calls in manual code, use real `virtual` methods on recovered classes — no
   local `typedef ...Fn` + `reinterpret_cast` blocks, no raw `vftable[...]` indexing,
   and no generated `VCall_*` facade wrappers.
10. When adding a dispatch to an unrecovered receiver, declare the method on the owning
    class header at the verified slot and call `obj->Method(args)` directly.
11. Rewriting `reccmp-project.yml` ignore lists is opt-in: only `just generate-ignores`
    and `just session-loop --refresh-ignore` do it; run them only when you explicitly
    intend to rewrite ignore configuration (`just session-loop` alone is read-only).
12. Mac CodeWarrior evidence (vendored at `vendor/macos_codewarrior/`) is a
    name/signature **oracle only** — it must never assign Windows addresses, calling
    conventions, vtables, or inheritance.
13. Never discard working-tree changes: no `git stash`, `git checkout --` /
    `git restore`, `git reset --hard`, or other blanket revert to escape a build/gate
    failure or "get a clean slate". Fix forward per the gate-chasing guardrail.
    Uncommitted changes may also belong to concurrent agents sharing this checkout —
    discarding them destroys in-flight work. Reverting requires an explicit user
    instruction.

## Hard rules: real C++ construction and inheritance

Mandatory. Do not use bridge thunks, placement-new shims, manual vtable writes, or fake
runtime helpers when a real C++ construct can express the same thing. Full recipes,
examples, and rationale: `docs/reference/construction.md`.

1. **Prefer real inheritance over construction bridges.** A structurally-derived class
   is `class TDerived : public TBase`, and its ctor calls `: TBase()` naturally — not
   `ConstructTBaseAtThis(this)` / `new (this) TBase()` / `VCall_RuntimeBaseCtor(this)`.
2. **No manual vtable writes** (`*(void**)this = ...`, `vptr = g_vtbl...`). The
   `// VTABLE:` annotation + C++ inheritance own vtable emission; a needed vptr write
   means the class model is wrong. Allowed only in quarantined runtime files with a
   comment proving it isn't normal construction. *(enforced by `just antipattern-gate`)*
3. **Constructor field init is about placement.** Use member-initializer lists (in
   declaration order) when the original writes scalar fields before constructing later
   non-POD members; body assignments force the member construction first and mismatch.
4. **Declaration order is part of the reconstruction** — C++ constructs members in
   declaration order. Match the original layout; do not reorder fields for looks.
5. **Use real member objects, not raw storage + init helpers** — declare a `CString`
   member as `CString`, not `unsigned char[4]` + `InitializeCString`. Raw storage only
   while the type is genuinely unknown.
6. **Compiler construction/destruction helpers are compiler output, not source-model
   APIs.** MSVC EH/vector iterator functions (`CallCallbackRepeatedly`,
   `InvokeCallbackNTimesWithSehGuard`, array constructors/destructors, cleanup callbacks,
   unwind helpers) and scalar deleting destructors must not be restored, wrapped, ported
   into invented helper TUs, or renamed as gameplay/runtime abstractions in manual game
   code. Do not keep them as "runtime helpers" either: in manual source they must
   disappear into real C++ source constructs. Recover the actual element/member type and
   let C++ member arrays, constructors, destructors, scalar deleting destructors, and
   inheritance emit those helper calls naturally. Never introduce `callback_helpers`,
   `CallCallbackRepeatedly`, `InvokeCallbackRepeatedly`, raw callback-address wrappers,
   or similar fake abstractions as a substitute for the real element type.
7. **Virtual calls are real virtual calls / real member methods**, not `VCall_*`
   facades or `reinterpret_cast` to fake calling conventions (see the guardrail below).
8. **No `operator new`/`operator delete` factories or `__cdecl` free-function factory /
   class-name helpers** (`CreateTViewInstance`, etc.) as a porting approach — port real
   methods + real inheritance. The retired "EH-new factory" pattern is not a template.
   *(baseline-tracked by `just antipattern-gate`)*
9. **No placement-new (`new (this) T()`) for base construction** — use real
   inheritance. Placement-new is only for genuine placement semantics (pools, explicit
   reconstruction into a buffer). *(enforced by `just antipattern-gate`)*
10. **Scalar deleting destructors (`??_G`/`??_E`) are compiler-generated** — claim them
   with `// SYNTHETIC` + an exact backtick name in `config/original_entities.csv`; never
   hand-write a `Destruct*AndMaybeFree` bridge. Requires a genuinely polymorphic class.
11. **Retire temporary scaffolding** (`Construct*AtThis`, `VCall_*Runtime`,
    `*AndMaybeFree`) as classes become understood; name any unavoidable bridge as
    temporary with a removal condition. *(count baseline-tracked by `just antipattern-gate`)*
12. **Don't corrupt the source model to chase a local score.** A 70% match with correct
    architecture beats a 100% match built on fake source that blocks hierarchy recovery.
    **This applies to gates too:** a failing `just gates` / `just vtable` with correct
    source is not permission to revert to stubs — see the gate-chasing guardrail below.
13. **Evidence required for inheritance** — base edges need constructor/destructor
    sequencing, vtable layout, prefix-layout, or Mac-symbol evidence; never names alone.

## Gate-chasing guardrail (never revert architecture to pass verification)

When `just gates`, `just vtable`, `just build`, or pre-commit checks fail **after** you
have promoted real C++ shape — typed fields, real methods, `new T()`, typed singleton
globals — **never undo that work to make verification pass.** Regressing from real
methods back to `extern undefined4` + `reinterpret_cast` at the callsite is strictly
worse than a failing gate and is treated as a source-model corruption (construction
Hard Rule 11).

### Typical failure mode (do not repeat)

1. Port real shape: named fields instead of `this + offset`, `g_pX->Method()` instead of
   a free-function stub, `new TNetMgr()` instead of a heap shim.
2. A gate fails (`just vtable`, duplicate `// FUNCTION:`, `antipattern-gate`, link error).
3. Agent **reverts step 1** — restores stub casts, `new char[]` buffers, or deletes the
   promoted method — so the gate passes.

Step 3 is **forbidden**. Fix forward or stop and report; never fix backward.

### Fix forward (in order)

1. **Build/link** — missing symbol: promote/own the callee as a real method, or use a
   genuine LIBRARY symbol (`operator new` at `0x606f73`, not a fake
   `AllocateWithFallbackHandler` stub). Wrong owner: fix the marker; stubs
   regenerate on the next build.
2. **Duplicate marker** — one address, one owner; move `// FUNCTION:` to the class that
   owns the method, sync ownership, regen stubs. Do not delete the manual method.
3. **`just vtable Class`** — first `new T()` in manual code can expose a pre-existing
   class-model gap. Fix slot ownership / imports / missing overrides on that class; do
   **not** stop constructing the class and do **not** re-stub callsites.
4. **`antipattern-gate`** — prefer `new T()` over explicit `operator new` + placement;
   prefer real inheritance over bridge thunks. Do not replace `new T()` with stub dispatch.

If none of the above can resolve the gate **without** architectural regression, **stop
and report** what failed, what you tried, and what class-model work remains. A blocked
commit with correct source beats a passing commit with reverted stubs.

### Callee classification (pick once, do not flip-flop)

| Evidence | Correct model | Forbidden rollback |
|----------|---------------|--------------------|
| `mov ecx, …` / callee uses `[ecx+off]` | Real `__thiscall` method on owning class; `obj->Method()` | `reinterpret_cast` to `__thiscall*` on `undefined4` stub |
| Vtable dispatch | Real `virtual` on recovered class | Raw `vftable[i]` or `VCall_*` facade |
| `0x606f73` / `AllocateWithFallbackHandler` in listing | `new T()` (MFC `operator new` LIBRARY in `mfc_heap_library.cpp`) | `new char[n]` + stub ctor cast |
| `// LIBRARY:` in repo | Link against MFC; no stub definition | Add a fake `undefined4` stub |
| Genuine `__cdecl` free function, no `this` | Port the real callee when feasible; the legacy `extern undefined4` + typed-cast-at-callsite form is a bridge being retired, not a porting approach | — |

**The legacy typedef-cast form applies only to genuine free-function thunks.** It does
**not** permit re-stubbing a callee you have already verified is `__thiscall` on a
recoverable class because a gate failed.

### Promotion direction is one-way

Temporary bridges must be **retired**, not restored. Once a callsite uses
`g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(...)` or
`new TNetMgr()` / `TNetMgr::ConstructGlobalTurnEventQueueManager(...)`, do not put the
free-function stub or fake calling-convention cast back to unblock a commit.

## MSVC500 calling-convention guardrail

- **Ghidra's calling-convention attribution is frequently WRONG** (it default-labels
  unknown functions `__cdecl`; ~33% of "defined `__cdecl`" are really `__thiscall`, and
  it mislabels `__fastcall`/`__thiscall`/vtable dispatch). Treat every convention from
  Ghidra/decompiler output as a hypothesis to verify against the assembly (who sets
  `ecx`/`edx`, who cleans the stack), never as ground truth.
- **Model real classes with real methods/virtuals — do not fake calling conventions
  with `reinterpret_cast` to paper over Ghidra's labels.** This is the single most
  repeated correction. (`reinterpret_cast` to a `__thiscall` function pointer is
  enforced against by `just antipattern-gate`.)
  - If a call is `thiscall`, the callee is a class method: declare it as a real method
    on the real class and call `obj->Method(args)`. Do NOT cast a free-function pointer
    to a fake `__fastcall(void*, int /*edx*/, ...)` shape with a dummy `edx`.
  - If a call is a **vtable dispatch**, model the real C++ class with real `virtual`
    methods (in the correct slot order — verify the slot offset in the disassembly) and
    call `obj->Virtual(args)` directly on the owning recovered class.
- A `reinterpret_cast` that only adjusts a return type or argument types of a genuinely
  same-convention free function (e.g. a real `__cdecl(void)` thunk) is fine. Faking the
  *convention* (esp. thiscall-as-fastcall-with-dummy-edx) is not.
- For an unavoidable free-function bridge where no class can yet be modeled, prefer
  `__fastcall` and keep the bridge out of primary method bodies — but first ask whether
  the right fix is to recover the owning class.

## Type-modeling guardrail

- **Use the correct type, and the real MFC type when the data is one.** Model a field,
  parameter, or local as the actual type the original used — not `int`, raw
  `unsigned char[]` storage, or a hand-rolled struct standing in for a known type. When
  the layout/behaviour is an MFC class, declare it as that MFC type (`CString`,
  `CPtrList`/`CObList`/`CObArray`/`CTypedPtrList`, `CPoint`/`CRect`/`RECT`, `CWnd`,
  `CArchive`, `CRuntimeClass`, …) so members construct correctly and call sites use the
  real API instead of walking protected internals (see the `mfc-collections` skill and
  construction Hard Rule 5). A `reinterpret_cast` to reach a method is the smell that the
  underlying type is mismodelled.
- **Never borrow a type from a neighbouring signature.** A parameter labelled `TEvent*`
  on one method does not make the object passed there a `TEvent`. Confirm the object's
  real class first (its constructor/vtable, `config/recovered_globals.csv`, `original_entities.csv`,
  or the Mac oracle) before typing or casting. Distinct classes that merely share a layout
  region or a slot are *not* interchangeable — `PostCommand(TCommand*)` vs
  `PostAnEvent(TEvent*)` in the Mac evidence proves `TCommand` ≠ `TEvent`, so a
  `TCommand`→`TEvent*` cast is a genuine type pun, not an identity.
- **An opaque/polymorphic vtable slot takes `void*`, not one caller's type.** When
  different overrides interpret the same slot's argument differently (one caller passes a
  `RECT*`, another a `TCommand*`), type the parameter `void*` and do the interpretation
  (`static_cast<TCommand*>`) inside each override body. Every call site then converts
  implicitly (cast-free); confine the one genuine cross-type pun to a single spot in the
  body. Do not pick one caller's type and force the others to `reinterpret_cast`.
- **Type pointer-bearing fields as typed pointers** (`TEventHandler* targetHandler`, not
  `int field10`) and update the init helper's argument to match, so call sites pass real
  objects via implicit upcast with no cast. Exception: a single offset reused as both an
  `int` and a pointer in different methods must stay `int`/raw — do not force a pointer
  type onto a dual-purpose slot.
- **Renames and pointer↔pointer / int-as-int narrowing are codegen-neutral and safe.**
  reccmp pairs by address and these casts compile to nothing, so aligning a C++ identifier
  to the curated `original_entities.csv` name (reuse it — don't invent a third) and tightening types
  cannot regress a score; confirm with `just compare <addr>`. Update an override's
  signature in lockstep with the base, or it silently stops overriding (`override` fails to
  compile, or a new vtable slot is created).
- **Be opportunistic in touched code.** Whenever you are already reading or editing a
  function, class, or file for an unrelated task, take the chance to improve types/names
  per the rules above and fix any other issues you notice there (wrong types, stray
  `reinterpret_cast`s, junk names, obvious bugs) — even if you didn't cause them and even
  if fixing them isn't strictly required to close the task at hand. Don't go out of scope
  hunting for unrelated problems elsewhere; this is about not walking past a fixable issue
  in code you're already looking at.
- **Every global in `global_data_tables.cpp` must be declared in `global_data_tables.h`.**
  Consumer `.cpp` files must `#include "game/global_data_tables.h"` and use that
  declaration — never hand-roll a local `extern` re-declaration of a global that's already
  (or should be) declared there. When adding a new global to the `.cpp`, add its matching
  `extern` to the header in the same change. When touching a file that locally
  re-declares one of these globals, migrate it to the header include (opportunistic-fix
  scope above).

## Commit-message policy

**Pre-commit verification** (required before every commit):

1. `just precommit` — build + all gates + tooling tests + stats in one command
2. Review the stats deltas vs `config/reccmp_progress_baseline.json`
3. `just stats-baseline-update` — refresh the baseline; commit it with the source change

If gates fail or stats regress for reasons unrelated to your edit, stop and report
rather than committing around the failure. See `.cursor/rules/commit-workflow.mdc`.
Never revert promoted real C++ to pass gates — see the **Gate-chasing guardrail** above.

**Score wobble is not a regression.** Growing a TU or linking new code elsewhere can
flip commutative-FP operand order (100%→43% on untouched FP leaves), cause sub-1pp
register-allocation wobble in neighbouring functions, and re-pair nearby LIBRARY
functions — all in code you never touched. These phantom drops are not regressions:
never revert real structure, relocate globals, or contort the design to defend the old
score. Accept the delta and `just stats-baseline-update` (full pattern: the
`fp-matching` and `data-modeling` skills' wobble notes).

- Do not add routine execution entries to `docs/worklog.md`; keep `docs/worklog.md`
  as historical context only.
- Write clear commit messages that explain what changed, how it was verified, and
  any relevant score deltas or accepted residual risks.
- Don't duplicate the same long status across multiple files.
- Persist transferable matching lessons in the matching **topical skill's** field
  notes (`calling-conventions`, `ctors-dtors-eh`, `string-handling`, `fp-matching`,
  `codegen-shapes`, `data-modeling`, `big-functions`, `vtable-matching`,
  `class-recovery`, `mfc-collections`); loop-process lessons go to
  `.claude/skills/decomp-loop/heuristics.md`.

## Cursor Cloud specific instructions

Environment prep (install `uv`/`just`/Docker/host-`wine`, `uv sync`, and the one-time
`just docker-build` of the `imperialism-msvc500` image) is already done by the VM
snapshot + startup update script; only the notes below are non-obvious. To
re-provision a fresh host from scratch (system packages, Ghidra, original binary,
first build), run `scripts/bootstrap.sh` — it is the one-time bootstrap; the
per-session refresh stays just `uv sync`.

- **Start the Docker daemon before any build.** `dockerd` is not auto-started on a
  fresh session. Start it once per session (it needs the docker-in-docker workaround
  already configured in `/etc/docker/daemon.json` = `fuse-overlayfs`):
  `sudo dockerd >/tmp/dockerd.log 2>&1 &` (or run it in a tmux session). Then
  `sudo docker info` should report `Storage Driver: fuse-overlayfs`.
- **`just` calls bare `docker`.** User `ubuntu` is in the `docker` group, so a
  *newly started* shell can run `docker`/`just build` without `sudo`. Within a shell
  that started before the group took effect, wrap the command:
  `sg docker -c 'just build'`.
- **The original binary is present in the snapshot** at `orig/Imperialism.exe` (sha256
  `6afab8495db715fd9e719cffa74abe5ede4dd763428ff65d73be4edf16c9e691`), wired via the
  gitignored `.env` (`ORIGINAL_BINARY=/workspace/orig/Imperialism.exe`) and
  `reccmp-user.yml` (`targets.IMPERIALISM.path`). Do **not** run `just bootstrap-reccmp`
  — it refuses to overwrite the committed `reccmp-project.yml`; hand-write/keep
  `reccmp-user.yml` instead (workflows §0). These three files are gitignored and persist
  in the snapshot.
- **reccmp needs host-side `wine`** (installed): the compare/stats/roadmap tools run
  `cvdump.exe` via `wine`/`winepath` to parse the recompiled PDB. Prefix long compare
  runs with `WINEDEBUG=-all` to silence Wine chatter.
- **What works:** the whole loop — `just tooling-check`, `just test`, `just build`,
  `just detect`, `just resource-check`, `just compare 0xADDR` / `--file`, `just stats`,
  `just vtable`, `just datacmp`, `just gates`, `just precommit`, and the source-only gates.
  (`just compare`/`--file` exits non-zero when any listed function is below 100% — that
  is a score signal, not a setup failure.)
- **Still blocked:** running the game (`just run`/`debug`/`screenshot`) needs the full
  retail install (a `Data/` folder next to the exe), which is not present — only the exe
  was supplied.
- **Ghidra targets work in cloud** (`ghidra-*`, `ghidra-apply-source`, `refresh-inventory`,
  `restore-project`). The snapshot ships Ghidra 12.1.2 at `/opt/ghidra_12.1.2_PUBLIC`, the
  matching `.env` `GHIDRA_INSTALL_DIR`, and the LFS-pulled project export
  (`vendor/ghidra/exports/Imperialism.gzf`, sha256 in the sibling `.sha256`). The one gotcha
  is that a fresh shell does **not** inherit `GHIDRA_INSTALL_DIR` — export it before any
  `just ghidra-*` target: `export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC` (or
  `set -a; . ./.env; set +a`). Run `just restore-project` once per session to load the
  program into the Ghidra project (`Program already present` means it's ready); then
  `just ghidra-decompile 0xADDR`, `just ghidra-listing`, etc. all work.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:6cd5cc61 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->
