# Similarity Improvement Notes

The matching playbook: transferable tactics for raising `reccmp` scores on
`Imperialism.exe`. These are **tactics, not rules** — the Hard Rules live in
`AGENTS.md`, and mechanically-checkable rules are enforced by `just gates`
(see `quality-control`). Per-function execution detail, exact score deltas, and
dead ends belong in commit messages, not here.

When you learn a new transferable lesson (decomp-loop step 9), fold it into the
relevant theme below — keep one short rule plus one or two `0xADDR (NN%→MM%)`
evidence points. Do not append address-specific worklog entries here, and do not
restate a Hard Rule or a memory; link to it instead.

---

## 1. Confirm the target before rewriting

- `just compare 0xADDR` once first: a `jmp OtherFunction` diff means it's a thunk —
  implement a call-through wrapper and keep the heavy logic in the destination.
- Intra-module calls route through ILT thunks (`0x40xxxx jmp <impl>`); reccmp does
  not always auto-follow them in verbose diffs. Confirm the real target by
  disassembling the thunk in Ghidra before assuming a callsite mismatch.
- 5-byte ILT `jmp <target>` thunks (e.g. `0x004064e2 jmp TView::TView`) are
  non-semantic linker artifacts — never hand-write them with placement-new bridges,
  pointer casts, or manual vptr writes. The durable fix is real inheritance so the
  base ctor is referenced symbolically. See [[ilt-thunk-retirement]].

## 2. FPO and optimization pragmas (`#pragma optimize`)

The global build is `/O2 /Oy-` (favor speed, frame pointer kept). The original was
compiled per-TU with different settings, so this is the highest-frequency lever.

- **Leaf / no-op / small helper bodies are FPO** — wrap the file in
  `#pragma optimize("y", on)` to drop the frame pointer, or you get a spurious
  `push ebp; mov ebp,esp`. This alone takes `ret N` no-op slots and tiny getters to
  100% (`0x00495310` 53%→100%). Bulk no-op slots live in `src/game/noop_slots.cpp`.
- **MFC foundation/collection code is favor-size** — bracket those TUs/regions with
  `#pragma optimize("ys", on)` (FPO + favor-size). Size-vs-speed shows as `and [m],0`
  vs `mov [m],0`, `pop ecx` vs `add esp,4`, RMW `inc [m]`, and shared (not duplicated)
  return tails. This took the whole `CPtrList` node family 29–78%→100%.
  See [[favor-size-mfc-foundation]].
- **Complex EH-RAII bodies are usually NOT FPO** — forcing `("y")` makes MSVC promote
  `ebx`/`ebp` as scratch and diverge more. Measure both ways before committing.
- EH ctors are an exception: they carry the `fs:[0]` frame yet are still FPO in the
  original — add `("y", on)` even with the EH frame present.

## 3. Constructor matching = field-init PLACEMENT

For any class with a non-POD member (`CString`/`CArray`/`CPtrArray`/...), prefer
member-initializer-lists over body assignments, in **declaration order**.

- Body assignments force the member subobject to be constructed before the body, so
  the member ctor lands before the scalar stores. The original emits scalars-first,
  then the member ctor, then the derived vptr last. Converting the scalars the
  original writes *before* the member into init-list entries matches this.
  `TView::TView` (`0x0048a8e0`) 72%→100%; `TMilitaryUnitOrderState` (`0x5c2df0`)
  69%→86%. See [[ctor-field-init-placement]].
- A scalar the original writes *after* the derived vptr (genuinely in the body) must
  stay a body assignment. A base-class field can only be re-set in the body.
- Declaration order — not init-list order — controls construction order; field offset
  vs the non-POD member decides which phase a field lands in. Do not reorder fields
  for looks (AGENTS construction rule 4).
- MFC-style ctors that open `mov eax,ecx; xor ecx,ecx` **return `this`** — declare the
  return type as the class pointer and `return this;` (`CPtrArray` `0x00601baa`
  13%→100%, `CPtrList` `0x00601f1d` 9.5%→100%).
- The residual on EH ctors (~14%) is the partial-construction state machine
  (`mov byte [esp+N],1/2`); not worth chasing once architecture is right.

## 4. Vtable dispatch as real virtuals, not facades

The legacy `VCall_*` facade layer has been removed — always add real `virtual`
methods on the owning class and call `obj->Virtual()` directly. Real virtual dispatch
lets MSVC cache the vtable in a register across calls, matching the original. This is
AGENTS guardrail + [[model-real-classes-not-callconv-casts]].

- Verify slot **byte offset vs index** before converting: `index = byte/4` for most
  objects, but some generated GreatPower facades use a raw index (`SlotA1` = 0xA1).
  Grep the reccmp diff for the emitted `call [reg+0xNN]` after building.
- For opaque receivers whose class isn't recovered, use a local abstract "vtable-view"
  struct of pure virtuals up to the needed slot and cast the pointer to it — this
  works for `this` too (vptr is at offset 0), giving real `mov ecx; mov eax,[ecx];
  call [eax+slot]` without making the whole class polymorphic. `0x004df010` 34%→44%.
- Big-vtable classes (TGreatPower = 178 slots) self-dispatch to sibling slots on
  `this`; declare the **whole slot range** as real virtuals in one structural pass
  (bodies may temporarily delegate) so sibling calls resolve to real virtuals. Verify
  ownership against `config/function_ownership.csv` first — many no-op slots are owned
  by `noop_slots.cpp`. See [[next-tgreatpower-vtable-scope]].
- The slot macro arg / `// slot 0xNN` comments are **decimal** (slot 0xb0 = index 176).

## 5. Calling-convention recovery

Ghidra's convention labels are hypotheses, not truth (~33% of "defined `__cdecl`" are
really `__thiscall`; `__fastcall` labels are often wrong). Verify against the listing:
who sets `ecx`/`edx`, who cleans the stack. See [[cdecl-thiscall-mislabel]],
[[no-callconv-cast-bridges]], AGENTS "MSVC500 calling-convention guardrail".

- A body opening with `mov reg,ecx` / `[ecx+off]` is a real `__thiscall` method — put
  it on the real class and call `this->Method(...)`. Never `reinterpret_cast` to a
  `__thiscall` fn pointer (MSVC500 `C4234`; enforced by `just antipattern-gate`), and
  never fake it with `__fastcall(ptr, edx_dummy, ...)`.
- A `thiscall` on a global-pointer manager (`mov ecx,[global]; call`) is a real method
  on a typed struct pointing at that global, not a `__fastcall(ptr,edx,...)` cast.
- Stale Ghidra boundaries/prototypes: a live `ghidra-listing` may report "no function"
  while `symbols.csv`/reccmp still pair the body. Trust the pushed args and `ret N`
  over the autogen `(void)` prototype.
- `just scan-cdecl-thiscall` (tool `tools/ghidra/scan_cdecl_thiscall.py`) classifies
  candidates: verdicts `ecx_this`/`no_ecx`/`empty`.

## 6. ABI return contracts

- `ret N` size = signature truth. `ret 0x10` vs emitted `ret 8` is a missing-stack-arg
  signature mismatch — fix it before micro-tuning locals.
- MSVC500 returns structs (POINT/RECT) via a **hidden caller-allocated pointer** pushed
  as a stack arg, so `ret N` counts it. MFC fill methods are `T* Fill(T* out){...;
  return out;}` — they leave the out-ptr in EAX and callers chain on it. Model these as
  struct-returning / out-ptr-returning, not `void(out*)` (`GetCachedPosPoint` 16.7%→100%).
- A Ghidra `void` prototype can hide an intentional `AL` contract: if the body sets AL
  on the success/fallthrough path and a caller branches on it, model a `char`/flag
  return (`0x004ef700` reject=0/valid=1). `extraout_AL` after a call means that call
  returns the flag.

## 7. Data-symbol and vtable pairing infrastructure

reccmp pairs by **name** (stripping C-linkage underscore); values are irrelevant.

- When the original references a named data symbol (`+ g_X (DATA)`, `[g_pX (DATA)]`)
  but the recomp emits a bare immediate, define the global as a real `extern "C"`
  symbol with the EXACT `symbols.csv` name (zero-fill fine) and reference it directly.
  See `src/game/global_data_tables.cpp`. Pointer globals: `void* g_pX = 0;` replaces the
  non-matching `ReadGlobalPointer(imm)` shortcut.
- To convert a `g_vtbl<Class>` manual-vptr-write ctor into a real polymorphic ctor:
  make it `class X : public Base` with a `// VTABLE:` annotation and real `override`s,
  write a plain ctor with NO manual vptr line, delete the `g_vtbl<Class>` global, and
  **delete the `g_vtbl<Class>` row from `config/symbols.csv`** — that last step is what
  makes it pair (otherwise DATA-vs-VTABLE mismatch). Caveat: only matches originals
  whose single vptr write is at the top of the derived body. See commit f6a0588 and
  AGENTS construction rules 1–2.
- Keep the manual write + DATA row only when the ctor is called by name / via jmp-thunk
  (a C++ ctor can't be addressed — see §3 and note on base-state methods) or when it
  deliberately skips an intermediate base.

## 8. Scalar deleting destructors

Compiler-generated `??_G`/`??_E` scalar deleting destructors must be SYNTHETIC, never
hand-written. Make the class polymorphic, the ordinary dtor implicit, and claim the
address with a `// SYNTHETIC` marker + exact backtick name in `symbols.csv`. Full
recipe in **AGENTS.md Hard Rule 16** and [[synthetic-scalar-deleting-dtor]];
remaining candidates in [[next-scalar-dtor-rollout]].

- A no-op custom `operator delete` lowers the `??_G` match — prefer the real global
  delete unless the class genuinely overrides new/delete (`0x534740` 58.8%→81.8%).
- A `Destruct*AndMaybeFree` **name** is not proof of a destructor — read the body
  (false positives: `0x58f1a0`, `0x4a0190` are hit-test/render functions).

## 9. Class recovery discipline

Defer the full methodology to the `class-recovery` skill. Tactics:

- Run a local vertical slice (`just slice-discovery <Class> 0xADDR`) before attributing
  helpers/fields; separate evidence into `this` fields, real vcall wrappers, and
  global/helper calls. A helper *called from* a class method is not membership evidence.
- Persist `ClassCandidate` evidence (`class_candidate.json`) before editing layout;
  empty unknowns beat speculative edges. Class/method names from Ghidra are provisional
  ([[ghidra-names-provisional]]) — match by address/behavior.
- Mac CodeWarrior evidence (`just mac-evidence`) is a **name/signature oracle only** —
  never assigns Windows addresses, conventions, vtables, or inheritance (AGENTS rule 15).
  When it gives a signature with hidden stack args, test the signature before tuning.
- Ground a local list/queue struct by the **vtable its ctor writes**, not its Ghidra
  name — names frequently contradict the installed vtable. See
  [[cluster-vtable-ground-truth]], [[ui-vtable-hierarchy-ground-truth]].

## 10. Deserialization and stream shape

- Preserve aggregate read/write sizes from Ghidra (`0x0C`, `0x180`, ...) instead of
  expanding into element loops unless the original clearly does.
- Use stream-vtable read return values for loop bounds; do not reuse pointer params as
  scalar counts. Preserve original `short`/`int` loop truncation semantics.
- Keep refill stages (stream-read marker + conditional queue push) even if a simplified
  version compiles — omitting them caps similarity in the 20s–30s.
- Avoid defensive null-guards in hot legacy deserialization paths unless the original
  has them; extra guards usually hurt similarity.
- Prefer typed global-slot helpers (`ReadNationStateSlot`, ...) over raw address cursors.

## 11. CRT idioms are intrinsics, not hand loops

- A `do/while` decrementing `0xffffffff` then `~counter-1` is MSVC's `strlen`
  (`repne scasb`). Declare `extern "C" unsigned int __cdecl strlen(const char*);`,
  `#pragma intrinsic(strlen)`, call it (`0x00489070` 28.57%→100%).
- `memset`/`memmove` live at fixed CRT addresses (`memset` `0x005e9a90`, memmove-style
  `0x005e9cf0`/`0x005e8420`). Call through declared extern thunks + typed casts (rule
  14) so MSVC emits a direct `CALL rel32`; a raw-address cast emits a non-pairing
  indirect `call reg`.

## 12. Declaration-order drift bug

A duplicated or over-sized declaration shifts every later slot/field by a constant.

- The tell-tale is a hand-written byte-offset cast where a named member "should" work,
  or a diff showing `call [reg+0xNN]` / `[esi+0xNNN]` off by a constant from the named
  slot/field. **Fix the declaration** (delete dup decls, shrink the array) — don't add
  more casts. Array-indexed accesses off the array base are immune; only members
  declared after the insertion point shift.
- Applies to both vtable slot decls (`TListObject` realign, 2026-06-10) and field
  layouts (`TGreatPower.serializedStatusFlags` over-declared `[0x0D]` → `[8]`).
- Before promoting a standalone interface's calls to real virtuals on an MFC-derived
  class, verify each "override" actually overrides the base slot (matching signature) —
  a redeclared-but-not-overriding virtual becomes a NEW appended slot (+misalignment).
  See [[diplomacy-state-cleanup-progress]].

### 12b. Vtable-not-matching campaign: the five recurring defects (2026-06-21)

`override` is `#define override` (empty) in `compat.h` — MSVC500 has no override
keyword, so the compiler matches an override to a base slot purely by **name +
signature**. A derived "override" whose name/signature differs from the base virtual
is silently appended as a NEW slot → "Recomp vtable is larger than orig" + every later
slot shifts. Driving `Vtables not matching` down is mostly finding these. Five patterns,
all source-only (edit header/cpp → `just build` → `just vtable`; ignore manifests):

1. **Duplicate virtuals for one slot** — generated `Orphan*`/`cmd_slotN` placeholder
   decls PLUS hand-written typed decls for the same slots ⇒ 2× the slots. Delete the
   junk set, keep the real typed methods (TBehavior, TCommand).
2. **Wrong base class** — a class whose vtable shows TObject bodies (Serialize 0x485e90,
   WriteTo 0x485f70, ShallowFree 0x415ce0 at 0x08/0x14/0x24) but is modeled `: CObject`
   or base-less. Reparent to `TObject` and drop the redundant streamSlot/cmd_slot decls
   (TCommand→TObject, TStream→TObject). TObject vtable is 0x6485c0, 10 slots (0x00-0x24).
3. **Missing base virtuals** — base header stops short; derived "inherited" comments name
   slots the base never declares, so derived new/override virtuals land early. Add the
   missing virtuals to the base in slot order (TPtrList 0x64-0x78, TStaticText 0x1c4-0x1d4).
4. **Phantom trailing virtuals** — base declares `virtual` methods past the real vtable
   end (orig shows "not annotated" tail). De-virtualize them (TAnimation 3 trailing).
5. **Junk-named overrides** — derived overrides named `Free`/`OwnerPanel`/`OrphanX`
   instead of the ancestor's real slot name ⇒ appended. Rename the derived method to the
   exact base virtual name+signature (TCluster pending; the big cascade for clusters/
   ministers/great-powers/zones). Per-class, laborious; signatures must match exactly.

Plus a non-vtable infra tell: a slot-4 scalar-dtor mismatch where two `symbols.csv` rows
share the `Class::\`scalar deleting destructor'` name → reccmp mispairs our `~`. Make the
sibling-class row's name unique (TSortedPtrList vs sibling 0x649010).

## 13. Batch repeating templates

When a vtable region is one repeating template (e.g. TGreatPower score-factor slots
0x8e–0x9e = six shapes × {army,navy}), port it as a batch, not one-off: define the
shared float coefficients as named globals, apply `#pragma optimize("y", on)` across
the family (alone took it 26–70%→51–90%), and reconstruct loop shape from the
listing's FSTP slots (Ghidra's decompile of float-heavy code is garbage). Order-class
recovery for TGreatPower's pending-action slots is the related lever — see
[[order-class-recovery-cstring-blocker]] and [[next-tgreatpower-vtable-scope]].

## 14. General process

- Convert `just promote` output to compile-safe member-method C++ immediately; rewrite
  raw `void __thiscall Foo(T* this, ...)` blocks into real method signatures before
  building, then `just sync-ownership` → `just regen-stubs` → `just build`.
- If a readability cleanup drops the score, restore the higher-scoring body shape and
  keep the cleanup in helpers/typed views.
- Batch related edits, then a single build + `just compare` over the batch; don't chase
  the last few percent on architecture-correct bodies. See [[big-batch-quality-passes]].
- `just sync-ownership` is **additive only** — when you delete a function from source,
  hand-prune its `config/function_ownership.csv` row before `regen-stubs`, or the stale
  `manual` row blocks stub regeneration. See [[stub-regen-thunks-alias-collision]].
- After a vtable-dump correction, verify **every** declared virtual sits at the intended
  slot index — a skipped slot in the header shifts all later entries. Details belong in
  `docs/*_vtable_evidence.csv` / worklog, not here.

- **Shape-only class batch (`just gen-classes`)**: porting all remaining classes at once
  works only if you *defer bodies*. `gen-class --no-bodies` emits header + GENERATED
  DECLS + compilable **unmarked** cpp stubs (no `// FUNCTION:`/ownership/symbols), so
  the vtable still emits/pairs but nothing claims the heavily-shared slot addresses
  (claiming them is what made `sync-ownership` explode). Build blockers solved once and
  for all in the generator: classify slots against the **full ancestry** (not just the
  immediate base, which truncates/false-`new`s deep view vtables); propagate scalar-dtor
  kind down the chain; match override return types to the nearest ancestor *header*
  (C2555); dedupe duplicate slot names and sanitize invalid / bridge-shaped provisional
  names to `VTableSlotNN`; `render_header` pulls `game/mfc.h` + forward-declares game
  types; `compat.h` carries the Ghidra scalar typedefs. Bodies are the remaining
  per-class decomp-loop work; expect the aligned-100% count to dip until they're ported.
