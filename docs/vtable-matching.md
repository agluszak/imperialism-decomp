# Vtable matching: what's broken and how to fix it

Status doc for the campaign to drive `just vtable` to 100%. Baseline at the time of
writing: **254 / 319 vtables not matching** (HEAD). Most failures are the shape-only class
batch (commits `90b2e43`, `c42e348`): classes given a `// VTABLE:` annotation + generated
header/cpp whose declared virtual list does not reproduce the original vtable.

This is the durable companion to the work in `tools/workflow/gen_class.py`,
`tools/workflow/class_codegen.py`, and `tools/workflow/vtable_autofix.py`. Read
`.claude/skills/vtable-matching/SKILL.md` for the per-slot fix taxonomy first.

## TL;DR

The 254 failures are **one defect wearing many hats**: an `override` vtable slot is
declared in C++ with the wrong method name, so MSVC emits a **new appended virtual**
instead of reusing the inherited slot. The vtable then grows ("recomp larger than orig")
and every later slot shifts, cascading to every descendant. Fix the **name** and the slot
reuses; fix it on the **base** and the whole family cascades.

The secondary mess is that a class's truth is split across **four artifacts that drift**
(`.cpp` markers, `function_ownership.csv`, `symbols.csv`, generated `src/autogen/stubs/`),
reconciled after the fact by a pile of patcher scripts. The cure is to make the single
codegen pass emit a **self-consistent bundle** so nothing needs "correcting" afterward.

## How reccmp decides a slot matches (ground truth)

From `reccmp/compare/core.py` (installed under `.venv/.../reccmp/`):

- A slot matches **iff** both the orig pointer and the recomp pointer resolve to DB
  entities with `orig.recomp_addr == recomp.recomp_addr`. So a slot pairs when **our
  source owns the orig address** — a `// FUNCTION:`/`// SYNTHETIC:` marker (or a
  `symbols.csv` row) binds the orig address to our recompiled function — with no competing
  claim.
- ILT `jmp` thunks (orig addr in `0x401000–0x409fff`) are **auto-followed to their target
  only when the thunk address is *not* claimed** (no `symbols.csv` row, no marker). Claim
  it and reccmp stops auto-resolving → mismatch.
- `vtableNN` in the `just vtable` diff is a **byte** offset; slot index = NN / 4.

## Root cause in detail (the override-name defect)

A C++ `override` reuses the base vtable slot **only if its name + signature exactly match
the base virtual**. The shape-only generator named override slots from the manifest's
`ghidra_name`, which for inherited/override slots is a **stale cross-class junk label**
(`OrphanLeaf_NoCall_…`, `OrphanCallChain_…`). MSVC sees a name with no matching base
virtual → emits a **new** virtual appended at the vtable tail.

The authoritative slot→name mapping lives in the **hand-curated foundation headers**
(`include/game/TView.h`, `TEventHandler.h`), where each virtual is tagged with its slot:

```cpp
virtual void NoOpUiLifecycleHook(int arg);   // 0x37 0x48ab70
virtual void ApplyRectSlot110(RECT* rectBuffer);   // 0x44
```

The foundation `TObject → TEventHandler → TView → TControl` already matches 100%. The
broken layer is the **mid-tier bases**: `TPicture` (cascades to ~121 descendant slots),
`TNoHilitePicture` (84), `TPageView` (42), `TBuildingView` (36), `TDialogView`, … **Fix
bases first; descendants inherit the fix.** Process order = manifest `ancestry` length
ascending (ancestors are always shorter).

## What's implemented (in the working tree)

`tools/workflow/gen_class.py`:
- `_ancestor_header_slot_decls` — resolves an override slot's name + signature from the
  nearest **ancestor header**'s `// 0x<slotidx>` tag (the core fix), wired into
  `apply_ancestry_slots`. **Proven**: regenerating `TPicture` corrected slot 0x44 →
  `ApplyRectSlot110` and dropped it out of the "recomp larger than orig" list.
- `_symbols_name_map` — prefers the **`symbols.csv` curated name** for an owned slot (the
  registry of record) over the manifest's junk `ghidra_name`, so the header decl matches
  the `.cpp` body + ownership (fixes unresolved-external link breaks; e.g. slot named
  `Select` instead of `WrapperFor_thunk_…At00570ae0`).
- `_handcurated_defaulted_args` / `_apply_defaulted_args` — when a slot resolves to a
  method that a hand-curated header declares **with default arguments** (e.g.
  `IsSelected(short = -1, bool = true)`), reproduce the defaults so hand-ported callers
  that omit those args still compile (C2660).
- `reconcile_unmarked_stubs` + a trivial-stub rename in `merge_cpp_bodies` — keep the
  `.cpp` in step when an override slot is renamed; foreign-owned slots get an **unmarked**
  stub (the class declares the virtual but does not own the address).
- Scalar-dtor seed now emits the `~Class(){}` **body** (was marker-only → link break).

`tools/workflow/vtable_autofix.py`:
- `order_classes_bases_first` / `--ordered` (implied by `--all`) — ancestry-topological
  ordering so base fixes cascade within one pass.
- relaxed the collision refusal: foreign-owned override slots are **reconciled** (unmarked
  stub) rather than refusing the whole class.
- `_drop_externally_declared` — drop a generated DECLS line whose member a hand-curated
  header already declares, to avoid double declaration (C2535). **Note the regex must
  capture a leading `~`** (no `\b` before it) or a destructor `~Class` is mis-parsed as
  the constructor `Class` and the dtor decl is wrongly dropped → the implicit dtor + the
  `.cpp` body collide (C2084). This was the actual C2084 cause and is fixed.

26+ unit tests green (`tests/tools/test_gen_class*.py`, `test_vtable_autofix.py`).

## What's still broken (and how to fix it)

### E1 — scalar-dtor double body (C2084) — FIXED
Was caused by `_drop_externally_declared` dropping the generated dtor decl (regex tilde
bug, above). With the dtor decl present, header + `.cpp` agree, single body. Keep the
post-render invariant: **≤ 1 `Class::~Class(` definition per `.cpp`**.

### E2 — shared body ownership (the real ceiling)
Verified: `0x48f520/570/640` and `0x5708c0` are owned by **`TPictureResourceEntryBase.cpp`**,
which is **not in `TPicture`'s ancestry** — they are **siblings** sharing one physical
function for a slot. reccmp lets only one class own (mark) an address, so the other
sibling's slot gets an **unmarked stub and never pairs**. Two sub-cases:
- **Inheritance share** (the owner *is* an ancestor): the descendant must render the slot
  as `inherited` → no body, no marker; C++ fills it from the base vtable. Implement by
  having codegen consult ancestor manifests and treat a slot whose target equals an
  ancestor's slot target as inherited (canonical owner = highest ancestor with
  `override`/`new`).
- **Sibling share** (owner not in ancestry — e.g. `TPicture` vs `TPictureResourceEntryBase`):
  only one can own the address. The other stays unpaired on that slot. **Honest ceiling**:
  these classes reach high-but-not-100% unless a **common base is recovered** that both
  siblings inherit (a separate, larger `class-recovery` task). Do **not** fake it
  (AGENTS rule 11). The oversize fix still applies, so they stop being "oversized".

### E3 — GetRuntimeClass (slot 0x00) pairing
`symbols.csv` names the orig addr (e.g. `0x48efa0`) `TPicture::GetTPictureClassNamePointer`
while our method is `GetRuntimeClass`, so reccmp pairs the orig to a different recomp
entity and shows `no orig`. Fix: own slot 0 as a `// FUNCTION:`-marked `GetRuntimeClass`
body **at the orig address** and align the slot-0 `symbols.csv` row so orig → our recomp.
If a residual remains it is one slot — report, don't fake.

### E4 — referenced ILT thunk (e.g. `TBoycottButton` byte 0x110, thunk `0x404fe8`)
reccmp auto-resolves the `jmp` thunk only if the thunk address is **unclaimed**. A callsite
still references the thunk symbol, blocking a plain prune. Fix: repoint the callsite to the
real method (qualified base call, reuse `repair_thunk_migration.py`'s pattern), then drop
the thunk's `symbols.csv` row + any marker so reccmp auto-resolves. Fold the referenced and
unreferenced cases into one ILT pass.

### E5 — sweep build breakages (the current blocker)
Running `vtable-autofix --all --write` regenerates ~480 files. Most are shape-only stubs
(safe). Breakage comes from the **minority of classes with hand-ported bodies** whose calls
no longer match a regenerated decl:
- **default-args drop** (e.g. `this->IsSelected()` vs generated `IsSelected(short, bool)`)
  — fixed by `_apply_defaulted_args` (above); **requires a re-sweep** to take effect.
- **hand-curated `// X is compiler-generated (implicit virtual dtor)`** headers — must get
  exactly one generated dtor decl (the C2084/C2535 axis), handled by the tilde-regex fix.
- The `manifest-gate` reports DECLS "out of date" for every class until a **successful
  full regen sweep lands** — expected; it goes green once the sweep builds.

## The unifying fix: one consistent bundle, kill the patchers

Today the per-class truth is reconciled post-hoc by `correct-scalar-dtors`,
`prune-ilt-thunks`, `annotate-*`, etc. Make the **codegen emit the whole bundle
consistently** from the manifest:
- header DECLS (resolver-corrected names, null-tail suppressed, no dup with hand decls);
- `.cpp` (marked body/stub for owned slots, unmarked for foreign, exactly one SYNTHETIC
  `~Class(){}`);
- `symbols.csv` rows including the canonical ``Class::`scalar deleting destructor'`` name
  **directly** — exactly what `correct_scalar_dtors.py` patches afterward, and which
  `class_codegen.plan_symbols` already emits, so the separate step becomes dead;
- `ownership.csv` `manual` claim rows.

`sync-ownership`, `regen-stubs`, `reorder-marked-functions` stay as **global aggregators**
(whole-tree scan / MSVC chunking) but have nothing to "correct". The loop collapses to:

```
just vtable-autofix --all --write   # apply manifests → header+cpp+symbols+ownership
just sync-ownership && just regen-stubs && just build
```

A convergence driver (bases-first, one build per round, `--max-rounds`) should replace the
manual chaining.

## Verification

- Per-base: regenerate a base → build → `just vtable <Base>` loses its oversize warning +
  inherited mismatches; 2–3 descendants improve.
- Aggregate: `just vtable` not-matching count drops from 254, tracked per round.
- Tests: `pytest tests/tools/test_gen_class*.py tests/tools/test_vtable_autofix.py` green.
- Gates: `just gates` (the `manifest-gate` only goes green after a successful full sweep).
