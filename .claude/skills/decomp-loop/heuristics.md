# Similarity Improvement Notes

The matching playbook: transferable tactics for raising `reccmp` scores on
`Imperialism.exe`. These are **tactics, not rules** — the Hard Rules live in
`AGENTS.md`, and mechanically-checkable rules are enforced by `just gates`
(see `quality-control`). Per-function execution detail, exact score deltas, and
dead ends belong in commit messages, not here.

When you learn a new transferable lesson (decomp-loop step 9), fold it into the
relevant numbered theme below — keep one short rule plus one or two
`0xADDR (NN%→MM%)` evidence points. Do not append address-specific worklog
entries here, and do not restate a Hard Rule or a memory; link to it instead.
**Note numbers are stable identifiers** (commits and skills cite them): never
renumber an existing note; a new note takes the next free number, and a note
folded into another leaves a one-line pointer behind.

## Thematic index

- **Target confirmation & reccmp pairing**: 1, 7, 25, 32, 38, 39, 52
- **Constructors, destructors, EH locals**: 3, 8, 33, 41
- **Vtables, slots, virtual dispatch**: 4, 12 (12b/12c), 20, 44, 45, 53, 54
- **Calling conventions, ABI, signatures**: 5, 6, 26, 34, 40
- **Class recovery & attribution**: 9, 16, 22, 23, 24, 28, 37, 46, 49, 50
- **MFC surface, collections, inline budget**: 15, 18, 27, 35, 55
- **Streams & deserialization**: 10
- **CRT idioms & body-shape fixes**: 11, 43, 48, 51
- **Monolithic functions & TU layout**: 13, 19, 36
- **Process, batching, formatting, audits**: 14, 29, 30, 42
- **Codegen noise / phantom regressions**: 16, 18, 47, 51, 52

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
- **A self-`this` vtable-slot call whose arg count / `RET n` can't match the
  attributed class's slot means the function is mis-attributed.** Verify the slot by
  reading the real method body (`RET imm`, arg reads) against the callsite (count the
  `push`es before `CALL [vtbl+off]`); on mismatch, trace who loads `ECX` at the call.
  `0x4d3a60` was filed as `TCivToolbar` but its `this` is a `TCivMgr`; re-attributing
  let the finalize call become a real virtual. reccmp pairs by address, so the fix is
  moving the body to the right class file + `symbols.csv` rename — it unblocks
  real-virtual modeling rather than changing the score per se.

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
  ownership against `config/function_ownership.csv` first — no-op slot bodies live in
  their owning class files. See [[next-tgreatpower-vtable-scope]].
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
- `just scan-cdecl-thiscall` classifies candidates: verdicts `ecx_this`/`no_ecx`/`empty`.

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
- **`ret N` as a class discriminator for a vtable receiver.** When a callsite pushes
  **A** args to `call [vtable + byteOff]` but your candidate base's body at that slot
  is `ret M` with M ≠ 4·A, the receiver is **not** that base — it's a sibling subclass
  with its own slot there (the base's no-op stub is a shared placeholder, not the real
  signature). Model the receiver as its own vtable-view/class (see §4); don't cast to
  the base and fight signatures (`0x5d57b0`).
- **An empty `ret N` body still encodes its arg count.** A no-op base virtual compiled
  as `RET 0x4` takes one stack arg; don't read the empty body as "no params". Correct
  the arity on the **base declaration and every override** (headers + defs) plus the
  `symbols.csv`/`function_name_overrides.csv` rows, or the `override` macro silently
  desyncs the slot (§14). (Fixed across TEventHandler + TEditText/TMapMaker, `0x48a710`.)

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
  (a C++ ctor can't be addressed) or when it deliberately skips an intermediate base.

## 8. Scalar deleting destructors

Compiler-generated `??_G`/`??_E` scalar deleting destructors must be SYNTHETIC, never
hand-written. Make the class polymorphic, the ordinary dtor implicit, and claim the
address with a `// SYNTHETIC` marker + exact backtick name in `symbols.csv`. Full
recipe in **AGENTS.md construction Hard Rule 10** and [[synthetic-scalar-deleting-dtor]];
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
  never assigns Windows addresses, conventions, vtables, or inheritance (AGENTS rule 12).
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

### 12b. Vtable-not-matching: the five recurring defects

`override` is `#define override` (empty) in `compat.h` — MSVC500 has no override
keyword, so the compiler matches an override to a base slot purely by **name +
signature**. A derived "override" whose name/signature differs from the base virtual
is silently appended as a NEW slot → "Recomp vtable is larger than orig" + every later
slot shifts. Driving `Vtables not matching` down is mostly finding these. Five patterns,
all source-only (edit header/cpp → `just build` → `just vtable`):

1. **Duplicate virtuals for one slot** — generated `Orphan*`/`cmd_slotN` placeholder
   decls PLUS hand-written typed decls for the same slots ⇒ 2× the slots. Delete the
   junk set, keep the real typed methods (TBehavior, TCommand).
2. **Wrong base class** — a class whose vtable shows TObject bodies (Serialize 0x485e90,
   WriteTo 0x485f70, ShallowFree 0x415ce0 at 0x08/0x14/0x24) but is modeled `: CObject`
   or base-less. Reparent to `TObject` and drop the redundant slot decls
   (TCommand→TObject, TStream→TObject). TObject vtable is 0x6485c0, 10 slots.
3. **Missing base virtuals** — base header stops short, so derived new/override virtuals
   land early. Add the missing virtuals to the base in slot order (TPtrList 0x64-0x78,
   TStaticText 0x1c4-0x1d4).
4. **Phantom trailing virtuals** — base declares `virtual` methods past the real vtable
   end (orig shows "not annotated" tail). De-virtualize them (TAnimation 3 trailing).
5. **Junk-named overrides** — derived overrides named `Free`/`OwnerPanel`/`OrphanX`
   instead of the ancestor's real slot name ⇒ appended. Rename to the exact base virtual
   name+signature. Per-class, laborious; signatures must match exactly.

Plus a non-vtable infra tell: a slot-4 scalar-dtor mismatch where two `symbols.csv` rows
share the `Class::\`scalar deleting destructor'` name → reccmp mispairs our `~`. Make the
sibling-class row's name unique (TSortedPtrList vs sibling 0x649010).

### 12c. Retire ILT thunks by deleting the named `symbols.csv` row — don't cast them

When the original calls through an ILT jmp thunk (`CALL 0x409a11` → real target), reccmp
auto-resolves the thunk to the real function **only if the thunk address has no named
`symbols.csv` entry**. A named thunk row (`thunk_Foo`) makes reccmp compare
`call thunk_Foo` vs your `call Foo` as a literal symbol mismatch (caps the caller ~93%);
a row-less thunk resolves to 100% for free. Fix: **port the real target into its correct
file** (real body, `// FUNCTION:` marker, `sync-ownership`), delete the thunk's rows from
both `config/symbols.csv` and `config/thunk_map.csv`, then call the real function
directly — never declare the thunk with a typed signature and `reinterpret_cast` it, and
never whitelist a stub in `tools/stubgen.py` (both are banned hacks). Took
`TView::Refresh` 93%→100% (QuickDraw DC family). Watch conventions: MFC `CDC::FromHandle`
&c. are `PASCAL`/`__stdcall` — a `__cdecl` cast adds a spurious `add esp,4`.
See [[imported-thunks-block-vtable-resolution]], [[ilt-thunk-retirement]],
[[banned-operator-new-cdecl-factory]].

## 13. Batch repeating templates

When a vtable region is one repeating template (e.g. TGreatPower score-factor slots
0x8e–0x9e = six shapes × {army,navy}), port it as a batch, not one-off: define the
shared float coefficients as named globals and reconstruct loop shape from the
listing's FSTP slots (Ghidra's decompile of float-heavy code is garbage). See
[[order-class-recovery-cstring-blocker]] and [[next-tgreatpower-vtable-scope]].

## 14. General process

- Convert `just promote` output to compile-safe member-method C++ immediately; rewrite
  raw `void __thiscall Foo(T* this, ...)` blocks into real method signatures before
  building, then `just regen-stubs` → `just build`.
- If a readability cleanup drops the score, restore the higher-scoring body shape and
  keep the cleanup in helpers/typed views.
- Batch related edits, then a single build + `just compare` over the batch; don't chase
  the last few percent on architecture-correct bodies. See [[big-batch-quality-passes]].
- **Batch compare exists — never loop single `just compare` calls.** `just compare
  0xA 0xB 0xC`, `just compare --file src/game/X.cpp`, and `just compare-class X` all
  run reccmp once with `--json` (one PDB parse for any number of functions).
- `just sync-ownership` is **deletion-reconciling** (and `just regen-stubs` runs it
  automatically): `marker_sync` rows whose marker disappeared are pruned; curated notes
  (e.g. `mfc_runtime_macro`) are never pruned. If a deleted function's stub still fails
  to regenerate, check for a leftover curated row. See
  [[stub-regen-thunks-alias-collision]].
- After a vtable-dump correction, verify **every** declared virtual sits at the intended
  slot index — a skipped slot in the header shifts all later entries.
- `override` is a no-op macro under MSVC500 (§12b), so the build won't complain about a
  non-overriding declaration. **`just lint` (real clang) is the only check that enforces
  it** — run it after any base-virtual rename or derived-override edit, before trusting
  `just vtable`. (Caught a TWindow slot 0x60-0x63 rename desync.)

## 15. Real MFC surface — call it directly, don't model it

`include/game/mfc.h` includes the **real** `<afx.h>`/`<afxwin.h>`/`<afxcoll.h>`, and the
binary links retail `nafxcw.lib` (see [[real-mfc-linking-viable]]). So `CObject`, `CWnd`,
`CString`, `CPtrList`, `CRuntimeClass`, `POSITION` are the **actual MFC types with real
virtuals/methods** — never re-model them, and don't write raw `(**(code**)(*field+off))()`
against them.

- **Call the MFC method by name** and let it pair via a `// LIBRARY:` annotation (e.g.
  `CObject::IsKindOf` @0x606fc0 is annotated in `CObject.cpp`). A window dtor `[vtbl+4](1)`
  is just `delete cwndptr`; `[vtbl+0xc]` (slot 3) is `AssertValid()`; `CenterWindow`,
  `m_hWnd`, `SendMessageA` are all direct. Took `TWindow::Free` 0x48e2a0 from a stub to a
  faithful 62% with every call site matching (commit 6c69fe86).
- **Never C++-model an MFC class that's already in the header (`CWnd`, `CCmdTarget`,
  `CFrameWnd`, `CDocument`, `CDC`, …) — annotate it.** Mirror `CObject.cpp`/`CDocument.cpp`/
  `MfcRuntime.cpp`: a bodyless `// LIBRARY: IMPERIALISM 0xADDR` + `// Class::Method` comment
  pair (ascending address order), and rename the `symbols.csv` row at that addr to the real
  MFC name. **Caveat:** a LIBRARY function only pairs once our build actually *links* it —
  i.e. some manual code calls it. To "recover" an MFC-derived game class you do NOT model
  `CWnd` — you `class X : public CWnd`, LIBRARY-annotate the CWnd surface it calls, and
  write the real `new X(...)`. See [[cmcwindow-recovery-plan]].
- **A `RUNTIME_CLASS` arg is a data global**: `IsKindOf(0x64b5d0)` → add a `g_pClassDesc<Class>`
  char + `// GLOBAL:` marker at that addr (rename the `symbols.csv` `Class::classRuntimeClass`
  row to it), pass `reinterpret_cast<CRuntimeClass*>(&g_pClassDesc<Class>)`. Same recipe as
  the slot-0 `GetRuntimeClass` descriptors.
- **A "custom stack iterator" over a list field is usually MFC `POSITION` iteration.** A
  local `{pos, parent, flag, code, element}` struct whose advance helper walks
  `node{next@0, prev@4, data@8}` (reading `*(list+4)` = `m_pNodeHead`) is exactly
  `GetHeadPosition()` + `GetNext(pos)`/`GetPrev(pos)` over a `CPtrList`.
- **Generic-named callees are real functions, not "missing".** `FUN_00xxxxxx` is a defined
  function (just unnamed); a 5-byte `JMP` at `0x40xxxx` is an ILT thunk to a named target
  (`just ghidra-listing` the addr to resolve it). Forward-declare + call — minding the
  legacy typedef-cast thunk-signature trap (§12c).
- **Don't fake these two shapes — recover the class instead:** (1) a free callee invoked with
  `ECX=this` is a `__thiscall` *method* on that receiver; (2) `buf = operator new(sz);
  Ctor(buf /*ecx*/, args)` is a real `new RealClass(args)` expression (the banned
  EH-new-factory) — recover `RealClass` and write `new CMcWindow(this)` (ctor 0x493470).

## 16. Embedded subobject → expose via its real type

When a class embeds another polymorphic class as a region (its vptr is written at
`this+off` by a `Construct*BaseState` call, e.g. `TDialogBehavior` @+0x74 in TWindow/TControl),
expose it through the real type so callers dispatch **real virtuals**:
`reinterpret_cast<TDialogBehavior*>(&field74[0])`. Use this when the embedded object's
construction isn't modeled yet (avoids restructuring the owner's ctor). Match the access
form to the original: a straight `mov eax,[this+off]; call [eax+slot]` is **direct** access
(`reinterpret_cast<T*>(&field)->Method()`), while a `call [this_vtbl+0x1b8]` first is the
**virtual accessor** (`GetEmbeddedX()->Method()`) — using the wrong one adds/drops a call
(TWindow `DispatchEvent` 0x48dd10 direct vs `0x48dc90` via accessor). Reminder: an
explanatory comment goes **above** the `// FUNCTION:` marker, never between it and the
decl (§38).

- **Codegen-saturated TU fragility (symmetric x87 FP leaves cannot be pinned).** In a huge
  TU like `TGreatPower.cpp`, small commutative float leaves (`tableA[i] + tableB[j]`, e.g.
  the `ComputeMinisterSkillFloatSlot8*` family 0x4e0590–0x4e0690) sit at a codegen
  knife-edge: MSVC500 freely reorders the `fld`/`fadd` operands, and **any** recompile of
  the TU — the file or any header it includes — can flip a previously-100% leaf to 42.86%.
  They cannot be pinned from source. Consequences: (1) the remaining facades/casts in the
  GreatPower family are deliberate workarounds — batch any cleanup into one TU recompile
  and accept the flips (they're noise, §47); (2) the real de-risking fix is splitting the
  fragile leaves into their own small TU. Always run full `just stats` after editing a
  GreatPower-family file or its headers. See [[tgreatpower-tu-codegen-fragility]].
- *(Historical)* The 2026 shape-only class batch (260 classes as vtables-only) used a
  `gen-class --no-bodies` generator since retired (2026-07-02; `config/classes/` manifests
  no longer exist). Bodies are ordinary per-class decomp-loop work.

## 17. Type safety: distinct classes, opaque slots, and cast-free call sites

When a `reinterpret_cast` between two *named* classes looks necessary, stop — it is usually
a modeling error, and the fix removes casts rather than relocating them.

- **Don't infer an object's type from a neighbouring signature.** A method parameter typed
  `TEvent*` does not make whatever is passed there a `TEvent`. Confirm the object's real
  class from its constructor/vtable, `config/recovered_globals.csv`, `symbols.csv`, or the
  Mac oracle *before* typing or casting. Worked example: `ProcessQueuedWarTransitions`
  routes a `TNextTradeCommand` (a `TCommand`) into `DoEvent`'s `TEvent*` argument;
  `TCommand` ≠ `TEvent` (Mac evidence: `PostCommand(TCommand*)` vs `PostAnEvent(TEvent*)`),
  so that is a genuine pun in the original — keep that one cast, comment it, and type
  everything else correctly.
- **A polymorphic slot's parameter is `void*`.** If different overrides interpret the same
  vtable slot's argument differently (slot 0x0d: `TEventHandler` reads a `TCommand`, a
  `TView` draw path passes a `RECT*`), the honest base signature is `void* payload`; do the
  interpretation (`static_cast<TCommand*>(payload)`) inside each override body. Every call
  site then converts implicitly, and the single irreducible pun lives in one body. Picking
  one caller's type forces every other caller to `reinterpret_cast`.
- **Type pointer-bearing fields as typed pointers.** `TEventHandler* targetHandler` (not
  `int field10`) plus a typed init-helper argument lets call sites pass real objects by
  implicit upcast with zero casts.
- **But a dual-purpose offset stays raw.** `TEventHandler+0x18` is a resource-owner pointer
  in some methods and an `int` block-pool count in `TView::SerializeRecordList` — keep it
  `int`/raw and accept the localized casts; don't break one reading to purify the other.
- **Renames and pointer↔pointer / int-as-int narrowing are codegen-neutral — verify and
  proceed fearlessly.** reccmp pairs by address and these casts emit no bytes, so `just
  compare <addr>` should be byte-identical. Use this to align `vmethodNN` identifiers to
  curated `symbols.csv` names (reuse the name, don't invent a third) and tighten types.
  Catch: update an override's signature in lockstep with the base (§14). The TU-fragility
  caveat (§16) applies when the touched header feeds a saturated TU.

## 18. MFC convention/access traps + CMap embedded tables (extends 15/16)

Three traps make an MFC-surface helper look like game code needing modeling when it is
really a real MFC method to call directly:

- **`AFX_CDECL` varargs members look like `__thiscall` but are `__cdecl`.** MFC's variadic
  members (`CString::Format`, `AfxTrace`, …) take the hidden `this` as the **first stack
  arg**, not ECX. A leaf doing `MOV ECX,[ESP+4]` then `CALL <thiscall helper>` is such a
  member forwarding `this` to a protected internal — not a free function to port.
  (`0x5ff15e` *is* `CString::Format`; call `cstr.Format(fmt, arg)` + `// LIBRARY:`.)
  Contrast: `this` in ECX *on entry* = real method (note 15).
- **A tiny forwarder into a protected/AfxGetApp path is the library function itself.**
  `0x6185e4` calls the **protected** `DoMessageBox` — only the library fn can, so it *is*
  `AfxMessageBox(LPCTSTR,UINT,UINT)`. Same tell for any "wrapper" touching protected
  MFC members.
- **Verify access/convention against the docker image's `afx.h`, not modern docs.** MFC 4.2
  differs from current `CStringT` (e.g. `CString::FormatV` is protected here though public
  in modern docs). Grep the vendored/docker headers for the member and its access section.
- **Embedded CMap tables (extends 16).** A subobject laid out `{vtbl, m_pHashTable,
  m_nHashTableSize=0x11, m_nCount, m_pFreeList, m_pBlocks, m_nBlockSize=0xa}` (0x1c bytes)
  whose slot 0 is the *inherited* `CObject::GetRuntimeClass` is an MFC **`CMap<>`
  specialization**. Confirm K/V are scalar via the dtor (frees only hash buffer + plex
  chain, no per-element destruction). Model it as a real `CMap<K,ARG_K,V,ARG_V>` member —
  the genuine default ctor emits the `size=17/block=10` init byte-for-byte. Two different
  embedded vtables ⇒ two distinct instantiations. Example: `TModuleLibraryCacheTableStateB`
  @0x498f60 (see [[imperialismapp-keystone-initinstance]]).
- **First-time linkage of an MFC fn causes reccmp re-pairing wobble.** Newly-linked nafxcw
  code shifts the MFC layout, so nearby LIBRARY functions re-pair and a few swing ±1-2pp (a
  big single-fn drop is a mis-pairing artifact, not a real loss). Aggregate stays ~flat;
  refresh the baseline, don't revert clean real-MFC calls.

## 19. Monolithic functions must be ported as one inline body — never split into separate-TU helpers

A big original function (e.g. a switch-based dispatcher) is a *single* function at one
address. The build uses `/Ob1`, which only inlines `inline`-marked functions and never
inlines across translation units. Decomposing case bodies into free functions in another
`.cpp` yields a thin sequence of `CALL`s that can never match — a 4 KB dispatcher stuck
at ~5%.

- **Inline the bodies into the one function** (an `#include "..._switch.inc"` fragment
  between `case` labels works well). Wrap each case in its own `{ }` so per-case locals
  don't collide (MSVC500 keeps `for`-init variables in function scope; give each loop
  its own uniquely-named control variable rather than relying on the leak).
- **Genuine helpers go file-scope `static inline`** so `/Ob1` folds them back in; trivial
  one-line wrappers are best expanded at the call site.
- **Isolate a large/disruptive function in its own TU.** Adding the inline switch + its
  includes to a shared `.cpp` perturbed that TU's codegen and regressed 9 neighbours —
  TU-codegen fragility (§16) cuts both ways. A class method can be *defined* in a separate
  `.cpp` (`src/game/<Class>_<Method>.cpp`); reccmp pairs by address, so this is free.
  Worked example: `TSimMgr::AdvanceGlobalTurnStateMachine` @0x0057da70 in its own TU.
- Remaining gap is then ordinary matching work (e.g. hoisted function-scope `CString`
  pinning `this` in `ebx` — see §33).

## 20. "Same address in two sibling vtables" is inheritance, not COMDAT folding — check RTTI first

Two supposedly-sibling classes whose vtables point at *identical* original addresses for
several slots looks like linker folding of identical bodies. It isn't — this link does
not fold identical functions across TUs (§52). The real cause is almost always that one
"sibling" is the **base class** of the other, and the shared address is an inherited,
unoverridden virtual.

- **Check the RTTI ancestry before modeling either theory**: every vtable slot 0 is the
  `CRuntimeClass` getter, and the descriptor's `+0x10` is `m_pBaseClass` — an intact
  ground-truth chain. `uv run python -m tools.ghidra.vtable_slots "ClassA=0xVTABLE"`
  prints the full ancestry as a side-effect log line. Cheap and deterministic — run it
  before ever writing a "shared/COMDAT-folded" comment.
- A derived ctor calling the *grandparent's* ctor directly is just the trivial parent
  ctor being inlined — not evidence against a normal inheritance edge.
- **Fix once the real base is confirmed:** repoint the base, delete the duplicate
  override decls+bodies for genuinely-inherited slots (address matches the base's own),
  fix the ctor init list. Slots with a *distinct* address are genuine overrides — keep.
- Worked example: `TBeachheadMission`/`TBlockadePortMission` really derive from
  `TControlSeaZoneMission` (not sibling of it); fixing the base took both vtables to 100%
  (+33 aligned functions). See [[tmission-comdat-fold-was-inheritance]].

## 22. Two adjacent same-typed fields always used together are probably one field

Two adjacent `short`s (from Ghidra's default per-access typing) that every usage
reads/writes as a pair are usually **one** 4-byte field: check the write site (usually
the ctor) for a single `mov dword ptr [this+off], reg`. The split shape costs real score
where a caller compares the combined value in one op (two `cmp`s instead of one
`cmp dword`). Evidence: `TShip` +0xc was two shorts; one `int` restored the single
`cmp dword ptr [x+0xc],0` in `TZone::HandleKeyDown` (17.25%→28.85%).

## 23. "Same free-function name, different receiver class" — make the shared logic receiver-agnostic

A helper reading fields at fixed offsets may be called with *more than one* receiver
class that happens to carry compatible fields there (common for sibling "order node"
types used as generic queue payloads). Promoting it to a member of one class silently
miscompiles the other call site. Instead: make the shared computation a plain function
taking the **values** as parameters, and give each class a thin member wrapper
forwarding its own fields. Evidence: `ComputeNavyOrderPriorityContributionPercentByCategory`
(0x54ff00) is called on both `TShip` and `TMapOrderEntry` nodes.

## 24. One "table" read at five different offsets is one struct, not five globals

Ghidra names a global by the *first* byte offset it sees, so a struct array accessed at
base/+4/+8/+0x10/... becomes several separately-named "tables". Tell: `g_Foo_0x...`
globals 4–8 bytes apart, all indexed with the **same per-element stride** (every read
does `index * 0x24`). Verify in the disassembly (the decompile hides it), then merge
into one real struct type + one array; raw-offset accessors collapse into named field
reads. Evidence: five "navy order lookup tables" at 0x698108–0x69811c were one
`TNavyOrderResourceDescriptor[64]` — and the split had caused two real bugs (a
wrong-stride read and a read from a disconnected local buffer).

## 25. `function_out_of_order` (decomplint) is a pure textual-reorder fix

Marked `// FUNCTION:` bodies within one non-header `.cpp` must appear in ascending
address order (folded/by-name markers exempt). Purely cosmetic — definition order
doesn't affect codegen. Cut-and-paste whole comment+function blocks into order; leave
unmarked anonymous-namespace helpers where later code needs them textually first.
Verify with `just decomplint`; the reorder is a score no-op.
(`uv run python -m tools.workflow.reorder_marked_functions <file>` automates it.)

## 26. Free-vs-method is decided at the CALLSITE: the ECX-load + `ret n` test

`scan-cdecl-thiscall` on the callee alone under-detects methods whose bodies never touch
`this` (empty hooks, emitters whose state is all globals). The decisive evidence is the
caller: `MOV ECX, <global or object>` immediately before the `CALL`, plus callee-cleanup
`RET n` matching the stack-arg count, proves `__thiscall` — and the ECX source names the
owning class. Worked examples (2026-07-02): every turn-event emitter (0x5446a0..0x54c5a0)
loads ECX from `g_pGameFlowState` → TMultiplayerMgr methods; `GetActiveNationId` 0x581260
loads from `g_pLocalizationTable` → TSimMgr, exposing a repo-wide wrong-receiver bug.
Corollary: old no-arg `extern void F(void)` stubs at such addresses are the dropped-args
audit pattern ([[quickdraw-thunk-retirement-2026-07]]).

## 27. CList/CArray twin copies masquerade as class methods and vtables

A cluster of {ctor writing head/tail/count/free/blocks(+blockSize), dtor doing
walk+FreeDataChain, Serialize doing ReadCount+per-element Read/AddTail} adjacent to a real
class's vtable is a **per-TU template instantiation** (afxtempl CList/CArray compiled into
that TU) — the original had no ICF, so every TU has its own copy. Model the underlying
object (often a file-scope static reachable via an `InitStub`/atexit pair: `MOV ECX,<addr>`
in the static-init gives the object address, the ctor arg gives blockSize) as a real
`CList<...>`/`CArray<...>` global and call the public API; `/Ob1` re-inlines AddTail
identically (TNetMgr::Send 35%→65%). The twin-copy addresses themselves can't pair against
the single recomp COMDAT — leave them to autogen stubs. Linker switches do not fix this:
`/OPT:NOREF` is identical to baseline for the CList rows, while `/OPT:REF` discards
thousands of intentionally-unreferenced recomp bodies and collapses coverage. Bonus:
"mystery globals" inside the object footprint are member aliases (0x6a13e8 = the 0x6a13e0
list's m_pNodeTail).

## 28. Field-by-field snapshot copies are a struct-recovery oracle

When a function copies a record wholesale but element-wise, the bytes it SKIPS are the
struct's padding, and every separately-copied slice is a real field boundary. Evidence:
DispatchCityRedrawInvalidateEvent 0x54abf0 snapshots the 0xa8 record and skips exactly
0x09/0x3d/0x96-97, proving fields that had been folded into pads. Use the copy to refine
the record, then rewrite the copy through typed fields.

## 29. Comment reflow / formatting can silently eat reccmp annotations

clang-format with `ReflowComments: true` (the LLVM default) merges an adjacent
`// VTABLE: IMPERIALISM 0x...` (or GLOBAL/FUNCTION/SYNTHETIC/LIBRARY) line into a
preceding over-long prose comment — the annotation becomes mid-sentence text that reccmp
and every gate silently ignore (7 vtables + 1 global lost with all gates green).
`.clang-format` now pins `ReflowComments: false`. After formatting, diagnose with
`grep -rnE "// .*[a-z)\.] (VTABLE|GLOBAL|FUNCTION|SYNTHETIC|LIBRARY): IMPERIALISM" include src`
plus `grep -rn "IMPERIALISM$"` (annotation split across two lines). Repair = put the
annotation back on its own line immediately above the declaration; restored vtables
pair at 100% for free (390→397).

## 30. Typedef-cast externs drift; audit before trusting a signature

The legacy typedef-cast extern pattern (`extern undefined4 Foo(void);` + per-callsite
`typedef ... (*Foo_t)(...)` cast) has no single source of truth, so signatures drift
between files (same target cast four different ways across three mission files; one
caller dropped the only argument — TBlockadePortMission::ReadFrom, 56%→100% by porting
the callee). `just typedef-cast-audit` extracts every `*_t` typedef and reports
cross-file conflicts — run it when touching any `_fn(` callsite, and prefer porting the
callee outright (targets are usually small leaves).

## 31. (folded into note 29)

## 32. Mine reccmp diffs for global identities (`just global-xref-oracle`)

reccmp renders an unresolved original operand as `<OFFSETn>` while the recomp side
shows the real PDB symbol (`[g_Foo (DATA)]`). Each such positionally-paired mismatch
line is a vote that the original address belongs to that symbol; applying a voted pair
is just adding an `addr|name|||global||xref_oracle` row to symbols.csv — no marker or
rebuild needed. Round 1 (min 2 votes, no conflicts) moved 31 functions to 100%. The
conflict column doubles as an annotation-audit: consistent votes AGAINST an existing
row mean the row is probably wrong.

## 33. A local object with a non-trivial dtor forces MSVC's single-epilogue shape

A function-scope local with a destructor (e.g. `CString`) that the original constructs
*unconditionally right after the prologue* forces every exit path through **one shared
epilogue block** running the dtor, with early exits becoming `jmp`s to it. Scoping that
local inside one branch (naive "where is it used" reading) gives each exit its own
duplicated epilogue and decorrelates nearly every jump offset. Diagnostic: compare the
recomp's `call CString::CString` position against the original's first few bytes — if
the original constructs at entry, hoist the local to function scope even if only one
switch case reads it. Evidence: 0x57da70, hoisting one `CString` shrank the byte-size
gap from +62 to +1.

## 34. `extern undefined4 Foo(void)` stubs may be real methods on a *different* receiver — read the ECX load

A free-function stub called "with no receiver" can be a real `__thiscall` behind an ILT
thunk, and the receiver is not always `this`: in one switch case, two calls used
`ecx = g_pLocalizationTable` while a third used `ecx = this` (0x57da70 case 3), and a
guard condition read a field on that *other* receiver — the old port had guessed a
similarly-named field on `this`. Always re-derive receiver + field offset from the
`MOV ECX, …` immediately before the `CALL`. Also: a `PUSH <addr>` that reccmp renders as
`push "Literal" (STRING)` is a string-literal pointer — model it as a named `s_*_00ADDR[]`
`// GLOBAL:`, not `reinterpret_cast<void*>(0xADDR)`.

## 35. "Cached context singleton" globals dispatched via `[ecx+slot]` can just be real CDC*

Before modeling a mystery "surface context" class behind vtable-slot calls, check whether
the callees are already-linked MFC methods: `CDC::SelectObject` is `virtual` at slot 0x30,
`CDC::SetTextColor` at 0x38, while `SetMapperFlags`/`SetTextAlign`/`OffsetWindowOrg`/
`LineTo` are plain direct calls — a global dispatching through both a vtable slot AND
direct calls with the same `ecx` is almost certainly a genuine `CDC*`/`CFont*`.
Cross-check virtual-vs-direct against the vendored `afxwin.h`. Retyping
`g_pScopedMapQuickDrawDcHandleObject` from `void*` to `CDC*` dissolved hand-rolled
`+4` offset hacks into a plain member access. Also: struct-by-value MFC returns
(`CPoint OffsetWindowOrg(int,int)`) push a caller-allocated hidden pointer *last* —
a `SUB ESP,N` at entry that's never read back is often that scratch buffer.

## 36. Turn-event screen builders share one widget-block vocabulary

Every `turn_event_dialog_factory.cpp` screen builder (the 253KB giants, bd 1uj.51) is the
same repeating widget block — port by recipe from `just ghidra-listing`, not the decompile
(which degenerates to `func_0x0040xxxx` stubs, and some builders are split into fragments:
a listing ending without an epilogue continues in the next "function"). Per widget:
`new <WidgetClass>()` (size after `PUSH n; CALL 0x606f73` identifies the class) → parent =
`g_UiWidgetBuildStack006a13e0.GetTail()` (else head=widget) → `AddTail` →
`InitializeUiResourceEntryFrameAndParent(0, parent, offset[2], size[2], 0, 0, 1)` (0x4096b5)
→ tag/field stores → slots 0xa4/0xa8 = `SetEnabled`/`SetState` → style bytes + rect →
per-class tail call (slot 0x1c8 on pictures, `BindUiResourceTextAndStyle` 0x41b490 on text)
→ `g_pUiResourceContext = 0` (+ `RemoveTail` when the widget takes no children).
Out-of-line variants are real functions in `ui_resource_pool.cpp` (0x41b210/0x41b3a0/
0x41b450/0x41b490). First param is the `CWnd*` host; the event-code check is
`(short)nEventCode != 0xNNN → return 0`. Gotcha: MSVC schedules argument pushes early —
match pushes to callee-consumed counts, not adjacency to the nearest call.

## 37. Two independent recoveries of one class can hide behind different names — check GetRuntimeClass address identity

Before porting a "not yet ported" class onto a bead's named target, check whether its
`GetRuntimeClass`/`CreateObject` **addresses** already belong to a different manual class:
the RTTI oracle's descriptor-address column is the ground truth, and an exact address
match (not name similarity) proves two recoveries are the same game class. Evidence:
"TMilitaryUnit" (raw-pad surface model) and `TMilitaryUnitOrderState` (real ctor/vtable,
~86%) shared `GetRuntimeClass` body 0x5c2dd0 — one class recovered twice; the old model's
"unmodeled pad regions" decomposed exactly into the other's inherited fields. Fix = merge:
keep the better-evidenced class, move fields/getters, delete the duplicate file, rename
call sites, `just regen-stubs`, and rename the scalar-dtor's curated backtick row to
match. Note `config/rtti_class_oracle.csv` descriptor addresses are the `CRuntimeClass`
struct (`class<X>`), **not** the vtable — verify a bead's "vtable at 0xNNNN" claim via
the ctor listing before trusting it. TU-wide ripple on merge is accepted noise (§16/§47).

## 38. "Failed to find a match" after editing a marked function = detached marker, not folding

Symptom: after changing a marked function's signature/body, `just compare 0xADDR` flips to
**"Failed to find a match"** and every vtable referencing that slot drops ~2% (one slot of
~49). Before theorizing COMDAT/ICF folding, **check Hard Rule 3**: an explanatory comment
added *between* `// FUNCTION:` and the declaration detaches the marker, so the symbol
never pairs. Move the prose above the marker. `just marker-gate` catches it; bare
`compare`/`stats` do not — the "unpaired + all referencing vtables −2%" fingerprint is the
fast tell. (Folding is ruled out anyway: §52.) Evidence: `TStream::streamSlot70`
0x488c50, base + override 0%→100% once the marker sat directly on the decl.

## 39. Library vtable addresses need a decorated-symbol row, or every dtor pays

A statically-linked MFC vtable address (e.g. CObject's `??_7CObject@@6B@` at
0x66fec4) that only has a name-typed `global` row in `config/symbols.csv` classifies
the original-side reloc as DATA while the recomp side is VTABLE — reccmp then counts
a diff line in *every* destructor that stores it (the ubiquitous
`mov [ecx], offset CObject::vftable` tail of inlined base dtors). Fix: give the csv
row the decorated symbol (`66fec4|CObject::`vftable'|??_7CObject@@6B@||global||`) so
`match_symbols` pairs it exactly. One such row took `TViewMgr::~TViewMgr` 50%→100% and
improved ~50 functions. Corollary: a fully-optimized derived dtor can compile to a
*single* store of the root-base vtable + `ret`, so a 7-byte "SetXxxBaseVtable"
junk-named function called only from a scalar deleting destructor is that class's real
`~T()` — claim it with a `// SYNTHETIC:` block, never model it as a vtable-reset helper.

## 40. COM interfaces hide behind "channel/audio object" vtable dispatch

If a cluster calls vtable slots on an opaque object with the receiver PUSHED on the
stack (`PUSH EAX; CALL [ECX+0x34]`) instead of passed in ECX, it is a COM interface,
not a game class. Identify it by slot arithmetic against the real interface layout
plus API-specific constants (TSoundResourceManager's channels: slots 0x2c–0x50 =
IDirectSoundBuffer Lock/Play/.../Restore; 0x88780096 = DSERR_BUFFERLOST). Model it as a
minimal C++ interface class with `virtual ... __stdcall` methods in the exact retail
slot order (MSVC passes `this` as the hidden first stack arg for __stdcall members, so
codegen matches exactly); don't invent dummy-slot game classes. dsound.h isn't in the
MSVC500 toolchain — declaring the interface locally with real COM names is the right shape.

## 41. GlobalHandle/GlobalUnlock/GlobalFree pairs = windowsx.h GlobalFreePtr; paired free-blocks + EH state = a local descriptor class with inlined dtor

The repeated triple `GlobalUnlock(GlobalHandle(p)); GlobalFree(GlobalHandle(p))` is
the windowsx.h `GlobalFreePtr(p)` macro (vendored header has it) — write the macro,
not hand-rolled pairs. When a function with no visible C++ objects still carries an EH
frame whose unwind funclet frees a group of stack slots this way, those slots are a
real local class (ctor zeroes the fields, dtor runs the GlobalFreePtr pairs): model it
as a small stack descriptor class with inline ctor/dtor and the EH states fall out
naturally (WaveLoadDescriptor in TSoundResourceManager, 0x49c290/0x49c430).

## 42. Find unknown message handlers by scanning for AFX_MSGMAP_ENTRY records

To find who handles a custom window message (e.g. the 0x4ef repaint trigger), scan the
original binary's data for the 24-byte AFX_MSGMAP_ENTRY pattern `{nMessage, nCode,
nID, nLastID, nSig, pfn}` with pfn in the image range, then resolve the pfn ILT thunk.
The null terminator entry is followed (in this binary) by the class's window-class
string, which identifies the owner (CIncludeView's map at 0x6489e8 ends before
"AmbitGameWindow"). This is how CIncludeView was recovered as the real main-frame
paint host.

## 43. Two cheap recomp-side diffs to sweep in the near-miss (98–99%) band

Both surface as a *recomp-only* line in `just compare 0xADDR` (green `+`) with no
matching original line, and both are one-line source fixes on already-owned bodies —
no marker/ownership churn, so skip `regen-stubs`.

- **Trailing `+xor al,al` = a Ghidra `undefined` placeholder return that is really
  `void`.** A body written `undefined Foo() { …; return 0; }` makes MSVC emit
  `xor al,al` before the epilogue; the original returns void and emits nothing. Retype
  the decl **and** the definition to `void` and drop `return 0;`. (`undefined` is the
  1-byte placeholder; a 4-byte return would be `xor eax,eax` — at `0x5e5140` the
  original *does* `xor eax,eax` and the fix is the opposite: retype to `int`.) Swept 7
  (TDisplayMgr ×3, TMacViewMgr ×4) 94–98%→100% in one build. These are frequently
  virtuals in a "GENERATED DECLS" block introduced by that class — self-contained to
  change; run `just format` after (trailing `// slot` comments re-align).
- **Recomp-extra `test rX,rX; je …` = a null guard the original never had.** When the
  original loads a pointer and immediately dereferences it but the port wraps the call
  in `if (p != nullptr)`, delete the guard and call unconditionally.
  (`TInvadeMission::RefreshSlot40` 0x53f7d0, `TNumberText::ShallowClone` 0x4912b0,
  both →100%.)

## 44. A `call [eax+0xNN]` vs `call [eax+0xMM]` diff = wrong virtual at the callsite

Map byte-offset → named method with slot_index = byteOff/4 and the header's
`// slot 0xIDX` comments (repo convention even names methods by byte offset:
`Call30` = byte 0x30, `RefreshSlot40` = byte 0x40). Fix is swapping the method name at
the callsite, no signature change. (`TMission::ReadFrom` 0x5358a0 called
`RefreshSlot40()` where the original dispatches `Call30()`, 98%→100%.)

## 45. Extractor over-extends a class vtable to swallow adjacent one-slot vtables

The generated `// slot 0xNN … 0xADDR` block appends every non-NULL pointer up to the
next *known* vtable, so a class whose table is followed in memory by small helper
vtables (often 1-slot `stretch<T>`) gets those foreign slots mis-attributed. Tell: a
run of NULL slots (the real abstract tail) then 1–2 more non-NULL "slots" whose targets
operate on a different `this` shape (touch only `[ecx+4/8/c]` = a stretch header, not
the class's layout). Confirm by resolving the slot pointer and checking which *global*
installs it as a vfptr — that global is the real owner. Fix: move the `// FUNCTION:`
markers onto a real concrete subclass of the helper template, rename the symbols.csv
rows, and leave the helper vtables unannotated when they overlap the host's vtable DATA
region (pair by address marker to avoid the collision gate). Turned two empty
"TMapMaker" stubs (0x52a760/0x52c0a0) — really `SeaSegmentStretch/SeapointStretch::
GetOrAppendUnique` — from 0–9% into 93%/91%. Corollary: a `stretch<T>` element size
reads straight off the grow strides (`n*0x30`/fallback `n*0x18` ⇒ 0x18 element), and a
by-value append copies exactly `sizeof/4` dwords — independent structural evidence.

## 46. stretch<T> vs MFC CArray: realloc-double-or-fallback is the discriminator

Both are growable arrays with a `data/capacity/count` tail, but MFC `CArray` grows by
allocating a fresh block and *copy-constructing* elements across (new + copy + delete),
whereas the project's `stretch<T>` family reallocs in place — request `count*2*stride`
via `ReallocateHeapBlockWithAllocatorTracking`, and on failure realloc to the exact
`count*stride`. That realloc-double-then-exact-fallback shape (no element copy loop on
grow) means `stretch<T>`: model it as a real `class X : public stretch<T, Tag>`
overriding the single-slot append virtual, not an ad-hoc struct. Mac evidence names the
family `stretch<Seapoint>` / `stretch<SeaSegment>` with `Add/operator[]/OverStretch`.

## 47. All globals belong in global_data_tables — never architect around codegen noise

**Globals go in `global_data_tables.{h,cpp}`.** Declare every shared global in
`global_data_tables.h`, define it in the `.cpp` — including plain untracked subsystem
scratch tables. Do **not** stash a global in a subsystem `.cpp` with local `extern`s to
keep a widely-included header byte-identical: that was a wrong reaction to a phantom.

The phantom: recompiling a float-heavy TU flips commutative-FADD leaves
(0x4e0590–0x4e0690, `fld [tblA]; fadd [tblB]`) 100%→43% because MSVC reorders the
operands. `a+b == b+a` — **that "regression" is meaningless.** Ignore such flips — do
not revert real structure, relocate globals, or contort the design to defend a phantom
100%. Accept the delta and `just stats-baseline-update`. Same for sub-1pp
register-allocation wobbles in neighbouring functions when a TU grows.

Corollary: reccmp's per-function % is a matching *aid*, not a score to defend. A drop
caused by operand order, register allocation, or scheduling in code you did not change
is not a regression worth a single line of work.

## 48. Big matching-heavy function: use float (not double) locals to avoid an alien frame

A `double` local for a distance metric forces an 8-byte-aligned frame (`push ebp;
and esp,-8`) the original (which used `float`) never emits — storing the metric as
`float` removed the whole alien prologue on the 1073-byte
`BuildOverlaySpanRecordsFromQuadBorderLinks` (0x52cae0). Match the original's FP width.
Beyond that, a big function's score is dominated by the compiler's induction-variable
register choice, which source can't steer — expect ~30% structural and treat the
absolute aligned-byte gain as the win. (A large standalone function may live in its own
`.cpp` per §19 — but never move code between TUs to chase neighbouring
register-allocation noise; see §47.)

## 49. Thunk-only-caller thiscall methods are frequently mis-attributed — reattribute by `[this+off]` field layout, not the curated name

When a `__thiscall` method's *only* xref is an ILT thunk, the `ClassName::` prefix was
guessed from weak evidence (Hard Rule 6). Recover the real receiver from the body's
`[this+off]` accesses: (1) list them; (2) grep recovered class headers for a field at
that offset with a compatible type; (3) reattribute — symbols.csv rename, move the
marker, declare on the real header. reccmp pairs by address, so reattribution never
risks the score; it unlocks typed field/virtual access. Beware: a lookup on a *global*
inside the body is NOT evidence about the receiver's class. Evidence: the
civilian-order cluster was all mislabeled `TCivToolbar::` — `CanAssignCivilianOrderToTile`
(0x4d2f60) reads `[this+4]` as a `TCivUnit*` = `TCivMgr::selectedEntry`, so the owner is
TCivMgr; `CalculateDeveloperTilePurchaseCost` (0x518b40) reads a stride-0x24 table at
+0xc = `TMapMgr::terrainStateTable`. Residual is usually register allocation — don't chase.

## 50. Detangling a two-class "frankenclass": split by vtable, recover layout from accessor displacement

A single class carrying **two distinct `// VTABLE:` roles**, with methods matching only
6–60% because their `this+off` accesses assume the wrong base, is two classes merged —
often manager + contained element (`TTradeMgr` vt 0x66d990 had `TDealList` vt 0x66da38
bolted on; the real edge was composition: `categoryRankLists[]` holds `TDealList`
instances). Split procedure:

1. **Recover the layout from accessor disassembly, not the decompile.** MSVC folds
   `array_base_offset + field_offset` into one displacement, so place the member array
   right after the vptr and shift struct field offsets accordingly; cross-check ctor
   cursor deltas and make the arithmetic total the RTTI object size exactly.
2. **Own every primary-vtable slot on the new class** (overrides + introduced virtuals
   in slot order) — honest `return 0;` bodies are fine; slot correctness is
   body-independent and `just vtable NewClass` hits 100% immediately.
3. **Retype the global + repoint the alias header**; the `// GLOBAL:` definition moves
   to `global_data_tables.cpp` (the marker gate rejects it anywhere else).
4. Getter param width matters: `MOVSX word` ⇒ `short` param — fixing offset + width took
   accessors 60→100%. Callers that now truncate may dip a couple pp; accept it
   (correct model > local caller score, construction Hard Rule 12).

## 51. Branch-order = fall-through: read the `je`/`jne` target to pick which body is the `if`

A listing opening `cmp x,5 / je <far> / <body...>` falls through to the INEQUALITY body,
so the source is `if (x != 5) { unequal } else { equal }` — writing the "natural"
`if (x == 5)` swaps the block order and misaligns the entire function (pinned ~25% until
inverted; `TMapMgr::ResolveMapTileVariantSpriteFromAdjacencyState` 0x5108d0). The Ghidra
decompile's `if/else` nesting does NOT encode fall-through; read the actual jump target
(near vs far). Related lessons from the same cluster:

- **An `int param` + `short s = (short)param` split is real, not decompiler noise**: when
  the body sign-extends (`MOVSX ebx,si`) but keeps the full dword live in another reg,
  model BOTH and use each where the decompile does. Collapsing to one `short` param
  removes a variable the original allocated.
- **A byte-compare-only field read is `MOV AL` / `CMP AL,imm` regardless of signedness**;
  signedness only forces MOVSX/MOVZX when the byte feeds arithmetic or a switch selector.
- **Don't cache a member pointer the original re-reads.** Caching `this->terrainStateTable`
  in a local consumed a register, forced a `this` spill, and shifted every `[esp+…]`
  offset (capped 14.6%); dropping the cache matched the frame (→32%, 0x510210). Mirror
  the original's caching decisions — a "cleaner" CSE can cost more than it saves.
- **Adding ~2KB of ported code can flip which recomp address reccmp pairs near-identical
  twin accessors to** (100→~43% on untouched functions). Layout noise, not a regression;
  confirm the net stats delta and absorb into the baseline (§47).

## 52. Confirm "Built target" before trusting any stats delta; this link does NOT fold identical functions

If one edit in a lockstep signature change silently fails, `just build` fails (C2511) —
but `just stats` still runs against the **stale** `.exe` and reports a large phantom
"-N aligned" regression. Always confirm the build printed `Built target Imperialism`
first; a whole session once mis-read this as an "ICF fold wall" and reverted correct
work. Empirical anchor: `/OPT:ICF` is **off** — two byte-identical `void f(){}` stubs
(0x596040, 0x596080) survive at distinct addresses — so byte-identical bodies never fold
here (see §20, §38); a real regression has a real cause. Related from the same cluster:

- **A "poison-pill" arg-count mismatch means the modeled arity is wrong.** The base
  no-op stub's `ret N` gives the true arg count (`ret 0xc` ⇒ 3 dwords); recover the
  signature from `ret N` + the overrides, then apply to the base and ALL overrides at
  once (five base stubs sat at 0–50% purely from being declared 0-arg).
- **A dispatcher that `CALL [EAX+byte]` after pushing args is a real virtual on `this`**
  (Hard Rules 9/10) — the 8-byte slot-0x79 dispatchers (0x51adc0/0x51c2f0) hit 100%
  once the target slot's true 3-arg arity was recovered.
- **The shared-ILT-thunk callsite is a permanent ~1-instruction miss** (recomp pairs the
  unscoped `thunk_X`, original the scoped `Class::thunk_X`) — a body whose only residual
  is that `call` caps just under 100% (0x51ad70 → 95.24%). Accept as inherent.

## 53. Recover a polymorphic NULL-abstract-slot's real receiver by scanning every vtable's byte offset

`TView` declares many high slots as NULL abstract placeholders that different subclass
trees fill with genuinely different-arity methods — so "byte 0x1e4" is not one method,
and a caller whose arg count contradicts the slot's arity in the class you *assumed*
means the receiver is a different subtree. Recovery recipe (proved the turn-event
'main' view is a `TDiplomacyMapView`, not a `TWorldView`):

1. Collect every `// VTABLE: IMPERIALISM 0x…` address (grep the headers).
2. For each vtable V, `just ghidra-read-data 0x<V+off> ptr` — keep non-null slots.
3. Resolve each filler's ILT thunk (`just ghidra-listing`), filter by the caller's
   needed arity via the target's `ret N`.
4. Map survivors back to vtable → class header; cross-check domain evidence (the class
   that also *stores* the tag constant is the receiver family). `just func-status`
   names the method.

Then wire the caller as `static_cast<TRealClass*>(resolve(...))->Method(args)` — a
codegen-neutral downcast plus the real virtual (0x5d7090 →100%). Different callers of
the same handler family can have different receivers — don't assume one recovery
covers the set.

## 55. Same inline function, two call shapes in one binary = per-TU inline-budget exhaustion, not flags or source tricks

When an MFC/afx.inl (or any header-inline) function appears BOTH folded away
(`call ::operator new` directly) and called out-of-line (`call CObject::operator new`
COMDAT copy at 0x41b1c0) for the *same* classes, do not invent a source-side model —
no class-scope operator overrides, no per-TU visibility macros, no per-file /Ob0.
MSVC500 gives each TU a finite inline-expansion budget: once exhausted, later calls
to `inline`-marked functions are emitted out-of-line (verified with the Docker
toolchain: a generated TU flipped after ~1750 expansions; the original binary's
factory giants flip mid-function — 0x415fe0 after 39 allocs, 0x41b6d0 after 10,
0x4601b0 never). Consequences: (a) such wrappers are LIBRARY code
(mfc_heap_library.cpp), never game ports; (b) reproducing exact flip points is a
TU-composition concern (which functions share the .cpp, in what order) to be tuned
when the TU is mostly ported; (c) `just alloc-audit` prints each original function's
inlined/out-of-line allocator sequence as ground truth, and `just decode-builder`
decodes builder bodies. Diagnostic tell: the out-of-line copy sits at a game-code
address adjacent to unrelated game functions (COMDAT emitted by whichever TU called
it first), and DYNCREATE CreateObject bodies always show the inlined form (small
functions, fresh budget).

## 54. Cross-check a header's assumed vtable-slot order against a REAL call site before trusting it

`TSortedList.h`'s `GetCount()`/`GetEntryByOrdinal()` are declared assuming they're the
first new virtuals after AddHead/AddTail-family slots (byte 0x48/0x4c), matching a
prior session's declaration-order guess — but a real, already-shipped call site
(`TCountry::SeedInitialMilitaryAndNavyOrdersForOwnedRegions`, 0x004d71b0) shows the
ORIGINAL binary dispatching `GetCount()`/`GetEntryByOrdinal(ordinal)`-shaped calls
(0-arg count check vs. 1-arg ordinal fetch, argument counts confirmed via `push`
presence and `ret N`) at byte **0x28/0x24**, not 0x48/0x4c — visible directly in
`just compare 0x004d71b0`'s diff (`-call [edx+0x28]` / `+call [edx+0x48]`). This
mismatch is NOT new-function-specific: it already caps that committed function at
56.50% and will cap every other `ownedRegionList`/`militaryUnitList44`-touching
function the same way (confirmed again independently in
`TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask`, 0x511f30 → 18.59%).
Don't trust a header's declared vtable slot order from declaration position alone —
before writing new code against a base class's virtuals, check ONE real call site's
raw disassembly (arg count via push+ret-N, not just address) against the header's
assumed byte offset. A full fix needs runtime evidence (ideally winedbg) for
TSortedList's entire slot layout, since even the class's own static vtable dump can't
disambiguate on its own (two different in-binary vtable copies for the same class
were checked, both self-consistent with the header's WRONG assumption for the early
slots) — this is flagged as follow-up work, not patched piecemeal per function.

## 56. A non-inline wrapper for a CList AddTail/RemoveTail COMDAT can't match the original's direct dispatch — and __inline makes it worse

The UI-builder giants call `g_UiWidgetBuildStack006a13e0.AddTail(node)` /
`.RemoveTail()` at every widget push/pop. The original emits each as a *direct
out-of-line dispatch* to the CList template COMDAT: `mov ecx, &list; call
AddTail@0x479b00` (thiscall, callee cleans stack, `ret 4`). The repo routes these
through free-function wrappers `Push/PopUiWidgetBuildStackNode` in
turn_event_dialog_factory.cpp so the AddTail body stays out-of-line. Two failure
modes, neither matches:
- **Wrapper NOT `__inline`** (called many times → past the TU inline budget, note 55):
  emits `call PushUiWidgetBuildStackNode` (a cdecl free fn) + caller `add esp,4`,
  vs the original's `call AddTail` + no caller cleanup. Mismatch at every push/pop,
  AND the cdecl call clobbers the register holding `parent`, forcing a stack spill
  that inflates the frame by 8 bytes (`sub esp,0x18` vs orig `0x10`) and cascades
  into dozens of wrong `[esp+off]` immediates.
- **Wrapper `__inline`**: MSVC inlines the wrapper, then also inlines the *template
  body* of AddTail/RemoveTail at each site (NewNode expansion + field writes), which
  is even further from the original's single `call AddTail`. Score went 64.31% ->
  59.94% on BuildUniversityDialogShell (0x4749a0) when both wrappers were marked.
The original's exact shape (direct `call` to the out-of-line COMDAT, no wrapper, no
body inline) is not reproducible from source at this build's `/Ob1`: a direct
`.AddTail()` call inlines the implicitly-inline template method, and any wrapper adds
a call layer. Keep the plain (non-inline) wrapper — it's the higher-scoring of the
two — and treat the residual push/pop call-shape + frame-size delta as an accepted
structural cost of these 10-15KB builders. Do not chase it by toggling `__inline`.

## 56. Byte-Boolean materialization: `sete/setne al + test al,al` means an unsigned-char Boolean, and int `BOOL` folds

When the original branches through a materialized byte (`xor eax,eax; cmp ...;
sete al; test al,al; je`) instead of comparing flags directly, the condition was
computed into a Mac-style byte Boolean (`unsigned char`/`char`), usually via a
file-local `static __inline unsigned char IsX()` helper or a byte local. Writing
the same condition as `BOOL` (int) or as a bare `if (expr)` folds to a direct
`cmp/jne` and loses ~3 instructions per site (SaveGameWithModeAndOptionalLabel
0x56da50 went 53%→92% on this fix alone). Corollary: return types the callers
test with `test al,al` are byte Booleans, not BOOL — e.g.
TryGetFileMetadataForPath (0x5d4c10) returns `(unsigned char)CFile::GetStatus(...)`.

## 57. `ret 4`/`ret 0` + caller `mov ecx, [global]` = thiscall singleton method with unused `this`

A "free function" whose every original callsite loads a manager singleton into
ECX and whose body never reads ECX is still a real `__thiscall` method on that
manager (callee-cleaned stack proves it): model it as a member with `this`
unused, not as `__cdecl`. Batch of five found this session:
TAssetMgr::SaveMainDocumentToPathAndMarkSaved (0x5e0030, g_pUiViewManager),
TOcean::FindFirstPortZoneContextByNation (0x563540, g_pActiveMapOrderContext),
TSimMgr::IsNationSlotEligibleForEventProcessing (0x581280, g_pSimMgr),
TNetMgr::ProbeNationReachabilityAndMarkAwolBitmask (0x5e43e0, g_pNetMgr006a6014),
TNetMgr::EnqueueOrSendTurnEventPacketToNation callers. The wrong free-function
model caps the score (~40-75%) and miscompiles every callsite (dead ECX setup +
caller cleanup).

## 58. Turn-event packet emitters: zero-then-value store pairs and their folding

The original packet emitters write each NetMessage header field twice — a zero
store then the real value, interleaved by the scheduler. Writing the same double
assignments in source (`packet.eventCode = 0; packet.eventCode = 0xb;`)
reproduces this in some TU contexts (TMultiplayerMgr.cpp when 0x54b5d0 hit 100%)
but folds to single stores in others (fresh TUs, grown TUs) — a TU-composition
sensitivity like note 55's inline budget, not a source-model problem. Keep the
double-write source; accept the folded-store diffs as the known wobble family.
A NetMessage default ctor zeroing the four fields is NOT the model: it groups
the zeros at the declaration point instead of interleaving them (verified, and
it regresses every other emitter).

## 59. Giant dispatchers get their own TU

Adding a multi-KB function to an existing TU re-shapes neighbouring functions
(store folding, register allocation) — 0x54b5d0 wobbled when 0x543910 landed in
TMultiplayerMgr.cpp. Follow the TSimMgr_AdvanceGlobalTurnStateMachine.cpp
precedent: put the monolith in its own file
(TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp) so its packet structs, inline
helpers, and optimizer footprint stay isolated.

## 60. Giant switch receive machines: transcribe per-case in binary body order

For a multi-KB `switch (packet->eventCode)` dispatcher (e.g. 0x545940, 42 cases,
11.4KB): (a) source case order must follow the binary case-BODY order, not numeric
order — MSVC5 lays bodies out in source order; (b) model the exits as plain `break`
per case + one post-switch `return 1` + `default: return 0` (the original's single
`mov al,1` / `xor al,al` tail pair comes from cross-jump-merged constant returns —
per-case `return 1;` statements compile to inline `mov al,1` copies that pair worse);
(c) give every event code its own packet-view struct derived from
NetMessage/TimelyMessageHeader/TimelyNetMessagePrefix and keep the exact store order
including double-writes; (d) an `if (x == tagA) A; else if (x == tagB) B; else C;`
chain whose bodies are emitted out-of-line with `je` jumps reproduces from
inverted-inequality nesting (`if (x != tagA) { if (x != tagB) { C } else B } else A`);
(e) accept the residual frame-size/stack-slot-order delta — VC5 slot assignment on
frames this large is not source-controllable (same anomaly class as 0x543280).
Parallelizing the asm transcription across subagents with a shared ILT->symbol map
document works well; verify every agent-supplied field/slot name against the repo
headers before splicing.

61. **Verify shared-class inline ctors against multiple original call sites before
    zero-initializing members.** CIterator's ctor stores ONLY ownerList in the binary
    (Reset() seeds nextPosition/current); our all-member init-list added two dead
    stores at every use site repo-wide. Fixing the ctor to match took several
    functions to 100% in one stroke (0x5a53e0, 0x59f890, 0x5c38e0). When a repeated
    small diff (same extra stores) appears across many functions using one helper
    class, suspect the helper's ctor/layout, not the functions.

62. **Never place a forward declaration between a `// VTABLE:` annotation and its
    class.** reccmp attaches the annotation to the next class-like declaration, so
    `// VTABLE: ...` + `class TOther;` + `class TReal {...}` silently pairs the
    vtable with TOther and fails `just vtable` with a confusing cross-class diff
    (hit three times in one session: TArmyTacUnit, TNavyBattle, TTacNavyToolbar).
    Put fwd decls above the class comment block.

63. **A multi-edit python splice that asserts mid-script loses ALL its edits** (the
    write happens at the end), and the failure mode is silent: the earlier "ok" prints
    never happened, the file keeps its old stubs, and compare pairs the address against
    the stale stub (1-5% scores with tiny `+0xADDR,2` recomp extents in the diff).
    After any batch splice, verify the bodies actually landed (`grep` a distinctive
    line per function) before building; prefer one write per replacement, or wrap each
    sub in its own try/write. Confirm suspicious "stub-like" scores by reading the
    recomp bytes at the paired address from build-msvc500/Imperialism.exe via the
    PE-parse pattern.

64. **A local whose live range ends at the accumulate gets `faddp`; one that lives to
    scope end gets `fxch/fadd/fxch/fstp`.** When the original shows the four-op
    shuffle around a `sum += term` (term preserved then dropped), the source declared
    the term variable OUTSIDE the loop (`double difference;` at function scope,
    assigned per-iteration). Hoisting the declaration took 0x5362c0 from 85.7% to
    95.05%. Corollary: intermediates that never spill to memory between FP ops were
    declared `double`, not `float` — float locals force rounding stores.

65. **`r = *rectPtr;` (struct assignment) vs member-by-member copies emit different
    code.** Struct assignment produces `lea dst` + temp-register member moves; four
    explicit `.left = p->left;` lines produce direct indexed stores. Match the
    original's shape (0x49f0c0 went 36.7% → 73.1% switching to struct assignment;
    same pattern earlier in TOneTimeAnimation's ctor). Similarly, zeroing an array
    through a named base pointer (`float* sums = arr; sums[0] = 0; ...`) reproduces
    the original's `lea` + offset stores where direct indexing does not.

66. **A body that never touches `ecx` can still be a `__thiscall` method — check the
    callsites, not the callee.** `FreeQuickDrawSurfaceContextSlot` (0x4feb50) looked
    `__stdcall` from its body (no `this` use, `ret 4`), but every caller loads
    `mov ecx, [g_pDisplayMgr]` first: it is a real TDisplayMgr method whose `this` is
    unused. Modeling it free-function silently deletes the ecx load at every callsite
    (~2 instructions x 34 sites). When promoting, sweep all callers to
    `g_pX->Method(...)` in the same change.

67. **Frame-slot packing is controlled by scope: block-scoped same-size locals pack
    into one slot; a function-scope local keeps its slot live to the end.** When the
    original has two iterator slots (0x18 and 0x24) but the recomp packs all loops
    into one, the original declared the early iterator at function scope (its
    lifetime crosses the later loops) while the case-local iterators packed into the
    second slot (0x59c440, 46.8% → 68.4%). Conversely a recomp frame LARGER than the
    original means block-scoped aggregates (RECTs) that the original reused as one or
    two function-scope buffers.

68. **A `func_0x` callee with an apparently different arg count at each call site is
    the ILT-thunk-ambiguity smell, not evidence of two functions.** `just ghidra-listing
    0xTHUNK` resolves the single real jmp target; if the decompiled param count still
    varies by call site (one shows zero args, another shows two), that's the
    decompiler failing calling-convention attribution at that specific site, not a
    real overload — read the callee's own decompile (its declared signature is ground
    truth) rather than trusting each call site's apparent arg list. When the callee
    turns out to be a genuinely murky/deep dependency (an MFC-internal-shaped cache
    with hash buckets and `CPlex`, or a whole GDI/CDC blit branch nothing currently
    exercises), it's fine to port the caller's shape faithfully and leave that one
    branch as a documented `// TODO(class-recovery)` no-op rather than chasing three
    more levels of unrecovered class layout — confirm first that no current caller's
    arguments actually reach the branch (e.g. every caller passes the sentinel/null
    that skips it) before leaving it unmodeled.

69. **Retiring a `reinterpret_cast<void(__stdcall*)(...)>(StubName)` bridge is a single
    fix applied at the declaration, not N per-callsite fixes.** Grep for the bridge
    pattern repo-wide before porting a stub free function — if 5+ files already call it
    through identical casts, porting the real typed signature once and then
    mechanically stripping the cast at each site (`sed`, since the pattern is
    syntactically uniform) both retires the anti-pattern and validates the ported
    signature (every call site's literal args must satisfy it, e.g. consistent
    `unsigned int` cast confirms real `__stdcall(unsigned int)`).

70. **MSVC500 for-loop-declared variables leak into the enclosing block scope (C89
    rules), so two sibling `for (int count = ...)` loops in the same braces is
    `error C2374: redefinition`.** Ghidra's decompile reuses one Ghidra-local name
    (`count`) for both loops since it doesn't model C++ block scoping; give each loop
    its own name when porting (`dwordCount`, `byteCount`) instead of copying the
    Ghidra name verbatim.

71. **A `Ghidra_name::WrapperFor_Construct<Class>BaseState_At0x...` that installs a
    *different* class's vtable (`this->vftable = &TOtherClass::_vftable_`) and/or writes
    `this[1].vftable` (past the object) is a COMDAT-folded construction fragment, not a
    real per-class ctor.** The linker folded several classes' identical construction tails
    into one address and Ghidra attributed it to whichever symbol it found first. Do NOT
    hand-port it as a fake per-class ctor (it would force a manual foreign-vtable write,
    violating construction Hard Rule 2). Leave it as a stub. Tell-tales: the `WrapperFor_`
    prefix, an installed vtable whose class name ≠ the `this` class, and tiny size.

72. **A base ctor that the compiler *always inlines* (no standalone out-of-line address —
    it appears only inside CreateObject and derived ctors) still gets a real C++ ctor
    body, just no `// FUNCTION:` marker.** Give it `: Base() { field = ...; }` so derived
    `: ThatBase()` chains construct correctly, and note in a comment that it is markerless
    because always-inlined (e.g. TPanelView). reccmp never pairs it (recomp-only, no
    marker), and derived ctors that call it score the usual accepted inlining-divergence
    band (80-86%) rather than 100%. This is the base half of the recurring ctor-inlining
    pattern: the real out-of-line base call our source emits vs. the original's inlined body.

73. **A trivial derived ctor can hard-fail reccmp pairing ("Failed to find a match at
    0xADDR") even when its same-shaped siblings pair fine** — our toolchain sometimes emits
    no uniquely-pairable out-of-line copy for one `: Base() { oneField = 0; }` ctor while
    emitting them for its siblings. Per the TNextMoveCommand precedent, revert just that
    marker (restore the markerless `{}` body) rather than faking it, AND manually delete
    the stale `config/function_ownership.csv` row — `just regen-stubs` reports
    "Pruned ... 0" and does not auto-remove it; the stub count only rises back after the
    manual delete + re-regen.

74. **A method whose every caller loads ECX from the same global belongs to that
    global's class -- Ghidra buckets orphan thiscall methods by address proximity,
    not by receiver.** The registry pair 0x4a0d10/0x4a0d30 sat under TCivAnimation2
    (whose code neighbours them) while every call site did `mov ecx,[g_pUiAnimator]`;
    the receiver global's declared type (TAnimator*) names the true owner. Check the
    callers' ECX source before accepting any orphan method's class bucket, then move
    the marker AND fix the class prefix in symbols.csv (the earlier TTaskList lesson).

75. **Run `just detect` after every build completes and before any `just compare`,
    even mid-session.** Comparing against a stale PDB right after a rebuild produces
    phantom "Failed to find a match at 0xADDR" hard-fails and wildly wrong low scores
    for functions that are actually 100% -- re-running detect then compare on the same
    addresses fixed five phantom failures in one batch. Never conclude a claim is
    unverifiable from a compare that ran before detect refreshed reccmp-build.yml.
