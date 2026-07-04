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
- **A self-`this` vtable-slot call whose arg count / `RET n` can't match the
  attributed class's slot means the function is mis-attributed.** Verify slot N by
  reading the real method body (`RET imm`/arg reads) against the disassembled
  callsite (count the `push`es before `CALL [vtbl+off]`, check for stack cleanup
  after). On mismatch, trace the caller: `xrefs_to` the function (and its ILT thunk),
  then read who loads `ECX` at the call (`MOV ECX,ESI` where `ESI=this` of a known
  class). `0x4d3a60` was filed as `TCivToolbar` (slot 0x0c = 0-arg `RET 0` stub) but
  its `this` is a `TCivMgr` (slot 0x0c = `RelinkCivilianOrderTileAndInvalidateMapTiles`,
  2-arg `RET 8`); re-attributing let the finalize call become a real virtual and
  dropped a spurious dummy-`edx` write (18.9%→19.6%). reccmp pairs by address, so the
  fix is moving the body to the right class file + `symbols.csv` rename, not a
  score change per se — but it unblocks real-virtual modeling.

## 2. (removed)

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
- **`ret N` as a class discriminator for a vtable receiver.** When a callsite dispatches
  `call [vtable + byteOff]` and pushes **A** args, the slot's true ABI is thiscall + A
  stack args. If your candidate base class's body for that same slot is `ret M` with
  M ≠ 4·A, the receiver is **not** that base — it's a sibling subclass with its own slot
  at that offset (the base's `OrphanRetStub`/no-op there is a shared placeholder, not the
  real signature). Don't cast to the base and fight signatures; model the receiver as its
  own vtable-view/class (see §4). Example: a `push 1; call [n+0x1a0]` callsite against
  TControl whose slot-0x68 body is `ret 0x14` (5 args) proved the node was a distinct
  TView-family dialog, not a TControl — modeled as `struct Node : public TView` with its
  own 0x68+ virtuals (`0x5d57b0`).
- **An empty `ret N` body still encodes its arg count — fix the arity everywhere.** A
  no-op base virtual compiled as a 3-byte `RET 0x4` takes **one** stack arg; don't read
  the empty body as "no params". When a callsite pushes an arg to a slot whose provisional
  decl is arg-less (`field64->vmethod_0081(0)` vs declared `vmethod_0081()` ← `0x48a710`
  is `RET 0x4`), correct the arity on the **base declaration and every real override**
  (both headers and defs) plus the `symbols.csv` / `function_name_overrides.csv` rows, or
  the `override` macro silently desyncs the slot (§14). (Fixed across TEventHandler +
  TEditText/TMapMaker.)

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

## 12b. Retire ILT thunks by deleting the named `symbols.csv` row — don't cast them

When the original calls a function through an ILT jmp thunk (`CALL 0x409a11` → real
target), reccmp auto-resolves the thunk to the real function **only if the thunk
address has no named `symbols.csv` entry**. A named thunk row (`thunk_Foo`) makes
reccmp compare `call thunk_Foo` vs your `call Foo` as a literal symbol mismatch (caps
the caller at ~93%). Contrast: a thunk with *no* row (e.g. 0x403729→BindScoped) resolves
to 100% for free. So the fix is to **port the real target into its correct file** (real
body, `// FUNCTION:` marker, `sync-ownership`), delete the thunk's rows from both
`config/symbols.csv` and `config/thunk_map.csv`, then call the real function directly —
never declare the thunk with a typed signature and `reinterpret_cast` it, and never
whitelist a stub in `tools/stubgen.py` to fake a signature (both are banned hacks). This
took TView::Refresh 93%→100% and ported SetGlobalQuickDrawOrigin / Bind+ReleaseScoped-
MapQuickDrawDcHandle from stubs to real owned bodies. Note MFC `CDC::FromHandle` &c. are
`PASCAL`/`__stdcall` (callee cleans stack) — a `__cdecl` cast adds a spurious `add esp,4`.
See [[imported-thunks-block-vtable-resolution]], [[ilt-thunk-retirement]],
[[banned-operator-new-cdecl-factory]].

## 13. Batch repeating templates

When a vtable region is one repeating template (e.g. TGreatPower score-factor slots
0x8e–0x9e = six shapes × {army,navy}), port it as a batch, not one-off: define the
shared float coefficients as named globals and reconstruct loop shape from the
listing's FSTP slots (Ghidra's decompile of float-heavy code is garbage). Order-class
recovery for TGreatPower's pending-action slots is the related lever — see
[[order-class-recovery-cstring-blocker]] and [[next-tgreatpower-vtable-scope]].

## 14. General process

- Convert `just promote` output to compile-safe member-method C++ immediately; rewrite
  raw `void __thiscall Foo(T* this, ...)` blocks into real method signatures before
  building, then `just regen-stubs` → `just build`.
- If a readability cleanup drops the score, restore the higher-scoring body shape and
  keep the cleanup in helpers/typed views.
- Batch related edits, then a single build + `just compare` over the batch; don't chase
  the last few percent on architecture-correct bodies. See [[big-batch-quality-passes]].
- `just sync-ownership` is **deletion-reconciling** (and `just regen-stubs` runs it
  automatically): `marker_sync` rows whose marker disappeared are pruned; curated notes
  (e.g. `mfc_runtime_macro`) are never pruned. If a deleted function's stub still fails
  to regenerate, check for a leftover curated row. See
  [[stub-regen-thunks-alias-collision]].
- After a vtable-dump correction, verify **every** declared virtual sits at the intended
  slot index — a skipped slot in the header shifts all later entries. Details belong in
  `docs/*_vtable_evidence.csv` / worklog, not here.
- `override` is a **no-op macro** under MSVC500 (`compat.h`: `#define override`), so a
  derived declaration whose name/signature drifts from the base virtual silently becomes
  a *new* vtable slot (extra slots, shifted layout) instead of an override — the build
  won't complain. **`just lint` (real clang) is the only check that enforces this**: it
  sees the genuine `override` keyword and errors on a non-overriding declaration. Run it
  after any base-virtual rename or derived-override edit, before trusting `just vtable`.
  (Found via a TWindow slot 0x60-0x63 `vmethod_009x` vs renamed `ReturnFromUiSlot6x`
  desync that broke the TGameWindow vtable.)

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
  MFC name (`CenterWindow` → `CWnd::CenterWindow`). reccmp then pairs the orig addr to the
  linked nafxcw function. **Caveat:** a LIBRARY function only pairs once our build actually
  *links* it — i.e. some manual code calls it (just like `CObject::IsKindOf` only paired
  after `Free` called it). Annotating `CWnd::CenterWindow` @0x60a27d lifted the calling
  wrapper 0x48e150 71%→74%; annotate the rest of the CWnd surface (`CreateEx` @0x608115,
  `WindowProc`, `OnWndMsg`, …) as the window code that uses them is ported. So to "recover"
  an MFC-derived game class (e.g. `CMcWindow : CWnd`, vtable 0x64b7c8 = the MFC message-map
  vtable) you do NOT model `CWnd` — you `class X : public CWnd`, LIBRARY-annotate the CWnd
  surface it calls, and write the real `new X(...)`. See [[cmcwindow-recovery-plan]].
- **A `RUNTIME_CLASS` arg is a data global**: `IsKindOf(0x64b5d0)` → add a `g_pClassDesc<Class>`
  char + `// GLOBAL:` marker at that addr (rename the `symbols.csv` `Class::classRuntimeClass`
  row to it), pass `reinterpret_cast<CRuntimeClass*>(&g_pClassDesc<Class>)`. Same recipe as
  the slot-0 `GetRuntimeClass` descriptors.
- **A "custom stack iterator" over a list field is usually MFC `POSITION` iteration.** A
  local `{pos, parent, flag, code, element}` struct whose advance helper walks
  `node{next@0, prev@4, data@8}` (reading `*(list+4)` = `m_pNodeHead`) is exactly
  `GetHeadPosition()` + `GetNext(pos)`/`GetPrev(pos)` over a `CPtrList`. Recognize the raw
  node walk and write the POSITION loop (TWindow `CallVoidSlotA0`/`DispatchSlot9C` child loops).
- **Generic-named callees are real functions, not "missing".** `FUN_00xxxxxx` is a defined
  function (just unnamed); a 5-byte `JMP` at `0x40xxxx` is an ILT thunk to a named target
  (`just ghidra-listing` the addr to resolve it). Forward-declare + call — minding the
  Hard-Rule-9 thunk-signature trap for free `__cdecl` helpers (§12b).
- **Don't fake these two shapes — recover the class instead:** (1) a free callee invoked with
  `ECX=this` is a `__thiscall` *method* on that receiver (model it on the receiver class, never
  reinterpret_cast a fake thiscall); (2) `buf = operator new(sz); Ctor(buf /*ecx*/, args)` is a
  real `new RealClass(args)` expression (the banned EH-new-factory) — recover `RealClass`
  (e.g. `CMcWindow : CWnd`, ctor 0x493470) and write `new CMcWindow(this)`.

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
explanatory comment must go **above** the `// FUNCTION:` marker, never between it and the
decl — a comment there silently unpairs the address (shows as `no recomp` / oversize vtable),
not just a marker-gate fail.

- **Shape-only class batch** *(historical — the gen-class/manifest tooling was retired 2026-07-02; config/classes/ manifests no longer exist)*: porting all remaining classes at once
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

- **Codegen-saturated TU fragility (symmetric x87 FP leaves cannot be pinned).** In a huge
  TU like `TGreatPower.cpp`, small commutative float leaves of the form
  `tableA[p->idx] + tableB[q->idx]` (e.g. the `ComputeMinisterSkillFloatSlot8*` family
  0x4e0590–0x4e0690) sit at a codegen knife-edge: MSVC500 freely reorders the `fld`/`fadd`
  operands, and which order it picks is sensitive to the *whole* TU. **Any** recompile of
  that TU — editing the file *or* editing any header it `#include`s (even a one-token
  virtual-parameter change in `TForeignMinister.h`) — can flip a previously-100% leaf to
  42.86%. They **cannot be pinned from source**: `double v = A; return v + B;` still emits
  `fld B; fadd A` because the compiler reorders across the temporary. Practical
  consequences: (1) the fake "view" facades and local `reinterpret_cast` bridges in the
  GreatPower family are *deliberate workarounds* to dispatch/pass-args without recompiling
  the fragile TU — "cleaning them up" trades those flips for architectural correctness
  (Hard Rule 11), so batch all such edits into one TU recompile and get maintainer sign-off
  on the regression; (2) the real de-risking fix is to split the fragile leaves into their
  own small TU so future edits stop perturbing them. Always run full `just stats` (not just
  the touched address) after editing a GreatPower-family file or its headers.

## 17. Type safety: distinct classes, opaque slots, and cast-free call sites

When a `reinterpret_cast` between two *named* classes looks necessary, stop — it is usually
a modeling error, and the fix removes casts rather than relocating them.

- **Don't infer an object's type from a neighbouring signature.** A method parameter typed
  `TEvent*` does not make whatever is passed there a `TEvent`. Confirm the object's real
  class from its constructor/vtable, `config/recovered_globals.csv`, `symbols.csv`, or the
  Mac oracle *before* typing or casting. Worked example: `ProcessQueuedWarTransitions`
  builds a `TNextTradeCommand` (a `TCommand`) and routes it through the slot-0x0d dispatcher
  into `DoEvent`'s `TEvent*` argument. `TCommand` ≠ `TEvent` (Mac evidence:
  `TApplication::PostCommand(TCommand*)` vs `PostAnEvent(TEvent*)`), so that is a genuine
  command-as-event pun in the original — not a class identity. Keep that one cast, comment
  it, and type everything else correctly.
- **A polymorphic slot's parameter is `void*`.** If different overrides interpret the same
  vtable slot's argument differently (slot 0x0d: the `TEventHandler` base reads a
  `TCommand`, but a `TView` draw path passes a `RECT*` to the same slot), the honest base
  signature is `void* payload`; do the interpretation (`static_cast<TCommand*>(payload)`)
  inside each override body. Every call site then converts implicitly — `RECT*`, `TCommand*`,
  `TNextTradeCommand*` all become `void*` with no cast — and the single irreducible pun
  lives in one body. Picking one caller's type instead forces every other caller to
  `reinterpret_cast`.
- **Type pointer-bearing fields as typed pointers.** `TEventHandler* targetHandler` (not
  `int field10`) plus a typed init-helper argument lets call sites pass real objects by
  implicit upcast (`TApplication*` → `TEventHandler*`) with zero casts. This is the
  field-promotion half of Hard Rule 8 applied to the *type*, not just the offset.
- **But a dual-purpose offset stays raw.** `TEventHandler+0x18` is a resource-owner pointer
  in the dtor / `SetUiResourceOwner` / detach / draw paths, yet an `int` block-pool count in
  `TView::SerializeRecordList`. An offset read as both an `int` and a pointer in different
  methods cannot be a pure pointer — keep it `int`/raw and accept the localized casts; don't
  force a single pointer type and break the other reading.
- **Renames and pointer↔pointer / int-as-int narrowing are codegen-neutral, so verify and
  proceed fearlessly.** reccmp pairs by address and these casts emit no bytes, so `just
  compare <addr>` should be byte-identical before/after. Use this to (a) align the generic
  `vmethodNN` C++ identifier to the curated `symbols.csv` name — reuse that name, don't
  invent a third — and (b) tighten field/parameter types. One catch: update an override's
  signature in lockstep with the base, or it silently stops overriding (`override` fails to
  compile, or MSVC spins up a new vtable slot). The TU-fragility caveat in note 16 still
  applies if the touched header feeds a codegen-saturated TU.

## 18. MFC convention/access traps + CMap embedded tables (extends 15/16)

When you reach an MFC-surface helper, three traps make it look like game code that needs
modeling/casting when it is really a real MFC method to call directly (see note 15):

- **`AFX_CDECL` varargs members look like `__thiscall` but are `__cdecl`.** MFC's variadic
  members (`CString::Format`, `CString::FormatMessage`, `AfxTrace`, …) are declared
  `AFX_CDECL` = `__cdecl`, so the hidden `this` arrives as the **first stack arg**, not in
  `ECX`. A leaf that does `MOV ECX,[ESP+4]` (load arg0 into ecx) then `CALL <thiscall helper>`
  is such a member forwarding `this` to a thiscall internal — **not** a `__cdecl` free
  function with an explicit object param, and **not** something to port. Worked example:
  `0x5ff15e` "FormatStringWithVarArgsToSharedRef" *is* `CString::Format(LPCTSTR,...)` (it
  loads `this`=dest from `[ESP+4]`, then calls the protected `FormatV` @0x5feeb8). Fix: call
  `cstr.Format(fmt, arg)` directly and `// LIBRARY:`-annotate the addr — no wrapper, no cast.
  Contrast with the real-thiscall rule in note 15 (this in `ECX` *on entry* = method).
- **A tiny forwarder into a protected/AfxGetApp path is the library function itself.**
  `0x6185e4` calls `AfxGetModuleState()->m_pCurrentWinApp->DoMessageBox(p1,p2,p3)` (vtbl+0x94)
  — `DoMessageBox` is **protected**, so a free function *cannot* call it; only the library
  fn can. That tells you `0x6185e4` **is** `AfxMessageBox(LPCTSTR,UINT,UINT)`. Call
  `AfxMessageBox(...)` directly + LIBRARY-annotate. Same tell for any "wrapper" that touches
  protected MFC members.
- **Verify access/convention against the docker image's `afx.h`, not modern docs.** MFC 4.2
  differs from current `CStringT` (learn.microsoft.com). e.g. `CString::FormatV` is
  **protected** in this MFC (afx.h ~line 599) though public in modern docs — so a free
  function genuinely can't call `FormatV`, which is *why* `Format` (the public AFX_CDECL
  member) is the right entry. Find it:
  `find / -path '*msvc/mfc/include/afx.h'` under the docker overlay, then grep the member +
  surrounding `public:`/`protected:`.
- **Embedded CMap tables (extends 16).** A subobject laid out
  `{vtbl, m_pHashTable, m_nHashTableSize=0x11, m_nCount, m_pFreeList, m_pBlocks,
  m_nBlockSize=0xa}` (0x1c bytes) is an MFC **`CMap<>` template specialization** when its
  vtable slot 0 is the *inherited* `CObject::GetRuntimeClass` (the concrete `CMapStringToPtr`/
  `CMapPtrToPtr` have their **own** `classRuntimeClass`, so a derived getter). Confirm K/V are
  scalar by reading the map's destructor — if it frees only the hash buffer + plex chain with
  **no per-element key/value destruction**, both K and V are scalar (rules out `CString` keys).
  Model the field as a real `CMap<K,ARG_K,V,ARG_V>` member: the genuine CMap default ctor then
  emits the exact `size=17/block=10` field-init **byte-for-byte** (much better than hand
  writes), and the owner ctor is `: m_field0(0), m_tableA(), m_tableB()`. Two *different*
  embedded vtables ⇒ two *distinct* instantiations (different K/V); exact scalar args fix the
  per-instantiation vtable but not the layout, so they can stay provisional (well-commented).
  Worked example: `TModuleLibraryCacheTableStateB` @0x498f60 (see [[imperialismapp-keystone-initinstance]]).
- **First-time linkage of an MFC fn causes reccmp re-pairing wobble.** Calling a nafxcw
  function the build never linked before (the stubs are `return 0`, they don't pull it in)
  adds that code and shifts the MFC layout, so reccmp re-pairs nearby LIBRARY functions and a
  handful swing ±1-2pp (a big single-fn drop like `CString::CString -68pp` is a *mis-pairing
  artifact* — recompiled simple ctor matched to a different original ctor, not a real loss).
  Aggregate stays ~flat; refresh the baseline. Don't chase these or revert clean real-MFC
  calls to avoid them.

## 19. Monolithic functions must be ported as one inline body — never split into separate-TU helpers

A big original function (e.g. a switch-based dispatcher) is a *single* function at one
address. The build uses `/Ob1`, which only inlines `inline`-marked functions and never
inlines across translation units (no LTCG). So if you decompose the case bodies into
plain free functions in another `.cpp`, the recompiled body becomes a thin sequence of
`CALL`s and can never match the inline original — a 4 KB dispatcher stuck at ~5%.

- **Inline the bodies into the one function.** Put the per-case code textually inside the
  function (an `#include "..._switch.inc"` fragment between `case` labels works well). Wrap
  each case in its own `{ }` so per-case locals don't collide — MSVC500 leaks `for`-init
  vars to the enclosing block (Hard Rule 10), and braces give each case a fresh block.
- **Genuine helpers go file-scope `static inline`** so `/Ob1` can fold them back in; trivial
  one-line wrappers are best expanded at the call site.
- **Isolate a large/disruptive function in its own TU.** Adding the inline switch + its
  extra includes to a shared `.cpp` perturbed that TU's codegen and regressed 9 neighbours
  (incl. a `vftable` 100→60% and two fns →0%) — the TU-codegen-fragility lever
  ([[tgreatpower-tu-codegen-fragility]]) cuts both ways. A class method can be *defined* in a
  separate `.cpp` (`src/game/<Class>_<Method>.cpp`); reccmp pairs by address, so this is free
  and keeps the neighbours byte-stable. Worked example: `TSimMgr::AdvanceGlobalTurnStateMachine`
  @0x0057da70 (4.96%→9.55%, zero neighbour regressions) in its own TU.
- Remaining gap on such a function is then ordinary matching work (e.g. the original hoists a
  single function-scope `CString` at entry, pinning `this` in `ebx`; a per-case local `CString`
  shifts register allocation across the whole body).

- **Batch compare exists — never loop single `just compare` calls.** `just compare
  0xA 0xB 0xC`, `just compare --file src/game/X.cpp`, and `just compare-class X`
  all run reccmp once with `--json` (one PDB parse for any number of functions).
  A per-address loop pays ~10s of PDB parsing per call for nothing.
## 20. "Same address in two sibling vtables" is inheritance, not COMDAT folding — check RTTI first

Two supposedly-sibling classes whose vtables both point at the *identical* original address
for several slots looks like linker COMDAT/ICF folding of byte-identical override bodies. It
usually isn't — MSVC500's plain link here does not fold identical functions across TUs (we
verified: porting each "shared" method as its own per-class override compiles to a *distinct*
recomp address per class, so the vtable slot never matches; `just vtable`/`just gates` then
fail with "Recomp vtable is larger than orig" + unpaired slots). The far more common real
cause is that one of the "siblings" is actually the **base class** of the other(s), and the
shared address is simply an *inherited, unoverridden* virtual — ordinary single inheritance,
zero linker magic required.

- **Check the RTTI ancestry before modeling either theory.** Every class vtable slot 0 is its
  `CRuntimeClass` getter; the descriptor's `+0x10` is `m_pBaseClass`, an intact ground-truth
  chain. Query it directly (no Ghidra GUI needed):
  `uv run python -m tools.ghidra.vtable_slots "ClassA=0xVTABLE"` (with `.env` sourced for
  `GHIDRA_INSTALL_DIR`) prints `ancestry ClassA -> ClassB -> ... -> TObject -> CObject` as a
  side-effect log line. This is deterministic and cheap — always run it before writing a
  "shared/COMDAT-folded" comment.
- **Corroborating evidence, if you want a second signal:** the derived class's constructor
  disassembly calls the *grandparent's* ctor directly (one hop, e.g. straight to `TMission`'s
  ctor) with no visible call to the immediate parent's ctor — this is just the parent's ctor
  being trivial enough to get fully inlined at every call site (verified by checking the
  parent's own standalone ctor: same flattened, call-free shape). It is not evidence against
  a normal single-inheritance edge.
- **The fix, once the real base is confirmed:** change the derived class's base from the
  wrong sibling/grandparent to the real immediate base, delete the duplicate override
  declarations+bodies for slots that are genuinely inherited unchanged (their address matches
  the base's own address exactly), and fix the ctor initializer list to call the real base's
  ctor. Slots where the "sibling" has a *distinct* address are genuine own overrides — keep
  those. Field layout is unaffected when the true base is the same size as the wrongly-assumed
  one, so no `ASSERT_SIZE`/offset changes are needed.
- Worked example: `TBeachheadMission` and `TBlockadePortMission` were modeled as direct
  `TNavyMission` children with 5 "COMDAT-folded" methods shared with sibling
  `TControlSeaZoneMission`. RTTI ancestry proved both actually derive from
  `TControlSeaZoneMission` (`TBeachheadMission -> TControlSeaZoneMission -> TNavyMission ->
  TMission -> TObject -> CObject`). Fixing the base class and deleting the bogus overrides
  took both vtables from "not matching" to 100% with zero score regressions elsewhere
  (+33 aligned functions, +0.57pp average similarity overall).

## 22. Two adjacent same-typed fields that are always compared/set together are probably one field

If a struct models two adjacent `short` (or other sub-word) fields purely from Ghidra's
default per-access typing, and every real usage reads/writes them as a pair (never
independently), check the disassembly for the *write* site (usually a constructor): a
single `mov dword ptr [this+off], reg` zeroing both in one instruction means the source
really declared **one** 4-byte field there, not two shorts ANDed together at every use.
Modelling it as two shorts is harmless for a plain equality-to-zero check (the compiler may
still fuse two `cmp` you can write as `a == 0 && b == 0`), but it's the wrong shape and can
cost real match percentage elsewhere (a caller comparing the combined value in one op will
now emit two `cmp`s instead of one `cmp dword`). Merge them into one field once the ctor
disassembly confirms a single wide write; there is no user of the codebase who needs the
narrower two-field view if no callsite ever reads them apart.

Worked example: `TShip::linkContext0c` + `linkTag0e` (two `short`s in the header) were
really one `int field0c` -- `TShip::TShip()` at 0x54f500 does one
`MOV dword ptr [ESI+0xc],EDI` (zero), and the only reader (`TZone::HandleKeyDown`, 0x55fc40)
tested equality-to-zero the same way. Splitting the check into
`linkContext0c == 0 && linkTag0e == 0` compiled to two separate `cmp`s and dropped that
caller from 28.85% to 17.25%; merging to one `int` field restored the original single
`cmp dword ptr [x+0xc], 0` and the 28.85% score.

## 23. "Same free-function name, different receiver class" -- make the shared logic receiver-agnostic

A function that reads fields at consistent offsets (e.g. +4/+0x1c/+0x30) may be called with
*more than one* receiver class if those classes independently happen to carry compatible
fields at those offsets (not uncommon for sibling "order node" types in this codebase, e.g.
`TShip` and `TMapOrderEntry` both used as generic queue-node payloads). Don't force it onto
one class as a member method if a second, unrelated call site passes a different class's
pointer to the "same" free function name — that's a sign that promoting it to a member
method would silently miscompile (or require an unsafe cross-cast) at the second call site.
Instead: make the shared computation a plain function that takes the actual **values** by
parameter (not `this`), and give each class a thin member-method wrapper that forwards its
own fields into it. Both callers get a real, typed call with no casts; only the numeric
values need to line up, not the class identity.

Worked example: `ComputeNavyOrderPriorityContributionPercentByCategory` (0x54ff00) is called
both on `TShip` nodes (`TNavyMission.cpp`'s primary order-list walk) and on `TMapOrderEntry`
nodes (`TNavyMission::ReturnZeroSlot2C`'s `orderList24` chain) — unrelated classes that just
happen to share `order_type`/`required_count`/`tiebreak_strength`-shaped fields at the same
offsets. Modeled as a free function taking `(resourceType, stockOrRequiredCount,
tiebreakField, category)`, with `TShip::ComputeNavyOrderPriorityContributionPercentByCategory`
as a one-line wrapper.

## 24. One "table" read at five different offsets is one struct, not five globals

Ghidra's auto-analysis names a global by the *first* byte offset it sees referenced, so a
single struct-array accessed at its base and at base+4/+8/+0x10/+0x14 etc. (by different
functions, or even by the *same* function through different-looking pointer arithmetic)
gets recorded as five separately-named "tables". Tell-tale sign: several `g_Foo_0x...`
globals whose addresses are 4/8 bytes apart and which are always indexed with the *same*
per-element stride (e.g. every read does `index * 0x24`, regardless of which "table" name is
in the expression). Verify by disassembly, not decompile pseudocode — the decompiler will
`MOV`/`MOVSX` from `[reg + 0x24*index + 0x1234]` for every one of the "different" tables at
consecutive constant offsets. Once confirmed, merge into one real struct type (named fields
at the recovered offsets, explicit `padXX` for gaps) and one array declaration; every
consuming file's raw-offset accessor helpers collapse into named field reads.

Worked example: `g_Resolve_Map_Order_LookupTable_00698108`, `g_Calculate_Mission_Order_LookupTable_0069810C`,
`g_Task_Force_Order_LookupTable_00698110`, `g_Navy_Order_Priority_LookupTable_00698118`, and
`g_ResourceDescriptorWeightWord0Base0069811c` were five "tables" 4-8 bytes apart, all indexed
by `resourceType * 0x24` — one `TNavyOrderResourceDescriptor[64]` struct array. This also
surfaced two real pre-existing bugs the split had caused: one already-ported function read a
table at the wrong stride (a factor-of-2 miscount from indexing a `short[]` by element instead
of by the real 0x24-byte stride), and another read from an entirely disconnected local
zero-filled buffer instead of the real game data (always returned 0).

## 25. `function_out_of_order` (decomplint) is a pure textual-reorder fix

Marked `// FUNCTION:` bodies within one non-header `.cpp` must appear in strictly ascending
address order (folded/by-name markers are exempt). This is purely cosmetic — C++ member
function definition order in a TU doesn't affect codegen or linkage, since the class header
already declares every member. Fix by cutting-and-pasting whole comment+function blocks into
address order; leave anonymous-namespace helpers and other unmarked prerequisites in place
near the top if something later in the file (now possibly reordered before its old position)
depends on them being textually visible first. Verify with `just decomplint` (or grep the
`function_out_of_order` count) before/after — the reorder should be a pure score no-op in
`just stats`.

## 26. Free-vs-method is decided at the CALLSITE: the ECX-load + `ret n` test

`scan-cdecl-thiscall` on the callee alone under-detects methods whose bodies never touch
`this` (empty hooks, emitters whose state is all globals). The decisive evidence is the
caller: `MOV ECX, <global or object>` immediately before the `CALL`, plus callee-cleanup
`RET n` matching the stack-arg count, proves `__thiscall` — and the ECX source names the
owning class. Worked examples (2026-07-02): every turn-event emitter (0x5446a0..0x54c5a0)
loads ECX from `g_pGameFlowState` → TMultiplayerMgr methods; `GetActiveNationId` 0x581260
loads from `g_pLocalizationTable` → TSimMgr, exposing a repo-wide wrong-receiver bug;
`NoOpDiplomacyPolicyStateChangedHook` 0x5033e0 (`ret 0xc`, body empty) loads from
`g_pHelpMgr` → THelpMgr method whose three args old ports had dropped. Corollary: old
no-arg `extern void F(void)` stubs at such addresses are the dropped-args audit pattern.

## 27. CList/CArray twin copies masquerade as class methods and vtables

A cluster of {ctor writing head/tail/count/free/blocks(+blockSize), dtor doing
walk+FreeDataChain, Serialize doing ReadCount+per-element Read/AddTail} adjacent to a real
class's vtable is a **per-TU template instantiation** (afxtempl CList/CArray compiled into
that TU), not class methods — the original was built without ICF so every TU has its own
copy of the template vtable + bodies. Model the underlying object (often a file-scope
static reachable via an `InitStub`/atexit pair: `MOV ECX,<addr>` in the static-init gives
the object address, the ctor arg gives blockSize) as a real `CList<...>`/`CArray<...>`
global and call the public API; MSVC500 /Ob1 re-inlines AddTail identically
(TNetMgr::Send 35%→65%). The twin-copy addresses themselves can't pair against the single
recomp COMDAT (known gap) — leave them to autogen stubs. Bonus: "mystery globals" inside
the object footprint are member aliases (0x6a13e8 = the 0x6a13e0 list's m_pNodeTail, i.e.
GetTail(); 0x6a5f6c = the session manager's lastErrorCode field, not a separate global).

## 28. Field-by-field snapshot copies are a struct-recovery oracle

When a function copies a record wholesale but element-wise (byte/word/dword slices, loops
per array), the bytes it SKIPS are exactly the struct's padding, and every separately-copied
slice is a real field boundary. Worked example: DispatchCityRedrawInvalidateEvent 0x54abf0
snapshots the whole 0xa8 TGlobalMapCityScoreRecord and skips exactly 0x09/0x3d/0x96-97,
proving shorts at 0x3e/0x40/0x94 and the CString city name at 0xa4 that were folded into
pads. Use the copy to refine the record, then rewrite the copy through typed fields.

## 29. clang-format eats `// VTABLE:` markers — keep them on their own line

Reflowing a comment block can merge a `// VTABLE: IMPERIALISM 0x...` (or split its address
onto the next line), which silently unpairs the vtable (it shows up as "unpaired now" in
stats, or as a long-missing vtable). After formatting headers, grep
`'\. VTABLE: IMPERIALISM'` and `'VTABLE: IMPERIALISM$'`; splitting the marker back onto its
own line re-pairs immediately (6 vtables recovered 2026-07-02).

## 30. Typedef-cast externs drift; audit before trusting a signature

The Hard-Rule-9 pattern (`extern undefined4 Foo(void);` + per-callsite
`typedef ... (*Foo_t)(...)` cast) has no single source of truth, so signatures drift
between files: the same target has been cast to four different signatures across three
mission files, one caller dropped the only argument entirely
(TBlockadePortMission::ReadFrom, fixed 56%→100% by porting the callee), and int-vs-float
argument confusion passed unit ids where the callee reads an x87 float.
`just typedef-cast-audit` (tools/workflow/check_typedef_cast_drift.py) extracts every
`*_t` typedef and reports cross-file signature/convention conflicts — run it when touching
any `_fn(` callsite, and prefer porting the callee outright (the targets are usually small
leaves; the whole 2026-07 mission-scoring cluster was 8 functions).

## 31. Comment reflow can silently eat reccmp annotations

clang-format with `ReflowComments: true` (the LLVM default) merges an adjacent
`// VTABLE: IMPERIALISM 0x...` (or GLOBAL/FUNCTION) line into a preceding over-long prose
comment, turning the annotation into mid-sentence text that reccmp and every gate silently
ignore — 7 vtables and 1 global had been lost this way with all gates green.
`.clang-format` now pins `ReflowComments: false`; the diagnostic is
`grep -rnE "// .*[a-z)\.] (VTABLE|GLOBAL|FUNCTION|SYNTHETIC|LIBRARY): IMPERIALISM" include src`
(plus `grep -rn "IMPERIALISM$"` for annotations split across two lines). Repair = put the
annotation back on its own line immediately above the declaration; the restored vtables
paired at 100% for free (390→397).

## 32. Mine reccmp diffs for global identities (`just global-xref-oracle`)

reccmp renders an unresolved original operand as `<OFFSETn>` while the recomp side
shows the real PDB symbol (`[g_Foo (DATA)]`). Each such positionally-paired mismatch
line is a vote that the original address (re-disassembled with capstone) belongs to
that symbol; symbols.csv is a reccmp `data_sources` entry, so applying a voted pair is
just adding an `addr|name|||global||xref_oracle` row — no marker or rebuild needed.
Round 1 (min 2 votes, no conflicts) moved 31 functions to 100% with zero regressions.
The tool's conflict column doubles as an annotation-audit: consistent votes AGAINST an
existing row mean the row (not the oracle) is probably wrong.

## 33. A local object with a non-trivial dtor forces MSVC's single-epilogue shape

A function-scope local with a destructor (e.g. `CString`) that the original constructs
*unconditionally right after the prologue* — not lazily where first used — is a strong
tell that every exit path (every `break`/`return`) must funnel through **one shared
epilogue block** that runs the destructor once, and every early exit becomes a `jmp` to
it instead of its own inlined pop/ret sequence. If you instead scope that local inside
one branch/loop (matching naive "where is it used" reading), the compiler has no reason
to build a shared funnel — each exit gets its own duplicated epilogue, inflating code
size and decorrelating nearly every jump-target offset in the function. Diagnostic:
compare the recomp's `push`/`call CString::CString` position against 0x<funcstart>+few
bytes in the original (before the first real branch) — if it's there, hoist the local to
the top of the function, unconditionally constructed, even if only one switch-case reads
it (pass it by value/const-ref into that case; it'll compile to a copy-ctor call per use,
matching original). Caught in `TSimMgr::AdvanceGlobalTurnStateMachine` (0x57da70):
moving `CString emptyString` from inside a case's loop to function-scope shrank the
byte-size gap vs the original from +62 bytes to +1 byte (1277→1116, target 1215) even
before any other fix landed.

## 34. `extern undefined4 Foo(void)` stubs beside a switch/state-machine may be real
    methods on a *different* receiver — check ecx, not just the name

A free-function stub called with no visible receiver can still be a real `__thiscall`
hiding behind an ILT jmp thunk (`0x40xxxx` range — resolve with
`just ghidra-listing 0xTHUNK`, never trust the un-followed `CALL 0x40xxxx` operand).
Two traps found together in one switch case: (1) the receiver is not always `this` —
`TSimMgr::AdvanceGlobalTurnStateMachine`'s case 3 called two methods with
`ecx = g_pLocalizationTable` (a *different* TSimMgr instance/alias) while a third call a
few lines later used `ecx = this`, in the same case body; (2) a condition guarding a
call can reference a field on that *other* receiver (`g_pLocalizationTable->redrawEnabled`
at +0x40) while the existing port had guessed a same-named-feeling field on `this`
(`this->field34`) — same bug shape as note 17's cross-class-cast trap, just via a global
alias instead of an inheritance cast. Always re-derive the field offset and receiver from
the raw `MOV ECX, [global]` right before the `CALL`, never assume `this`. Also watch
`RET 0xN` on the callee for the real stack-arg count/types (a `PUSH <addr>` operand that
reccmp later renders as `push "Literal" (STRING)` is a string-literal pointer, not a raw
int — model it as a named `s_*_00ADDR[]` `GLOBAL:` global per note 9/existing convention,
not `reinterpret_cast<void*>(0xADDR)`).

## 35. "Cached context singleton" globals dispatched via `[ecx+slot]` can just be real CDC*

Before modeling a mystery "surface context" class behind vtable-slot calls, check whether
the callee addresses are already-linked real MFC methods: `CDC::SelectObject(CFont*)` is
`virtual` at slot 0x30 and `CDC::SetTextColor` at slot 0x38 (see afxwin.h), while
`CDC::SetMapperFlags`/`CDC::SetTextAlign`/`CDC::OffsetWindowOrg`/`CDC::LineTo` are plain
non-virtual direct-address calls — if a "cached context" global dispatches through both a
vtable slot AND plain direct calls with the same `ecx`, it is almost certainly a genuine
`CDC*`/`CFont*`, not a custom class needing recovery (`g_pQuickDrawMemoryDc` was already
typed `CDC*`; the sibling fallback `g_pScopedMapQuickDrawDcHandleObject` at the *same*
address family (0x6a1d9c) was still `void*` with hand-rolled `reinterpret_cast<...>(...)
+4` offset hacks reaching for `CDC::m_hAttribDC` — retyping it to `CDC*` let those dissolve
into a plain member access). Cross-check: real MFC virtuals are declared `virtual` in the
vendored header (`vendor/msvc500/headers/mfc/include/afxwin.h`); non-virtual ones aren't,
matching the direct-vs-vtable call shape in the disassembly. Also: struct-by-value MFC
returns (`CPoint OffsetWindowOrg(int,int)`) use a caller-allocated hidden-pointer arg
pushed *last* (after the normal args) — `SUB ESP,N` at function entry that's never read
back is often this scratch return buffer, not a mystery local.

## 36. Turn-event screen builders share one widget-block vocabulary

Every `turn_event_dialog_factory.cpp` screen builder (the 253KB "return nullptr" giants,
bd 1uj.51) is the same repeating block, so port them by recipe, not by decompile — the
decompiler output for this cluster is degenerate (stack-tracking loss renders calls as
`func_0x0040xxxx` ILT stubs with args as stack-slot stores; some functions are also
split into fragments, see below). Read `just ghidra-listing` instead. Per widget:
`new <WidgetClass>()` (size after `PUSH n; CALL 0x606f73` identifies the class; the ctor
thunk resolves via a listing of the thunk address) → parent = build-stack tail data
(`[0x6a13e8]+8` = `g_UiWidgetBuildStack006a13e0.GetTail()`, else head=widget) →
`AddTail` (thunk 0x403643) → `InitializeUiResourceEntryFrameAndParent(0, parent,
offset[2], size[2], 0, 0, 1)` (0x4096b5; offsets land in `[ESP+0x2c/0x30]`, sizes in
`[ESP+0x34/0x38]` in later blocks) → `controlTag`/`field3c` stores → vtable slots 0xa4/0xa8
= `SetEnabled`/`SetState` → `flag4c/4d` bytes → style: `hasCommandTagResource` (+0x60)
plus the +0x68..+0x74 rect (CRect(0,0,0,0) copy) → per-class tail call (slot 0x1c8 =
`SetPictureResourceIdAndRefresh` on pictures, `BindUiResourceTextAndStyle` 0x41b490 on
text) → `g_pUiResourceContext = 0` (+ `RemoveTail` only when the widget takes no
children). Out-of-line variants of the same steps exist and are now real functions in
`ui_resource_pool.cpp`: `RegisterUiResourceEntry` 0x41b210, `SetUiResourceStateFlags`
0x41b3a0, `SetUiResourceLayoutValues` 0x41b450, `BindUiResourceTextAndStyle` 0x41b490
(the latter two hit 100%). The factory's first parameter is a `CWnd*` host window
(flows into the tail `PropagateUiResourceContextRecursive` call); the event-code check
is `(short)nEventCode != 0xNNN → return 0`. Gotcha: pushes before a 0-arg virtual call
(e.g. slot 0x1b8 `GetEmbeddedDialogBehavior`) may belong to the *following* call —
MSVC schedules argument pushes early; match pushes to callee-consumed counts, not
adjacency. Also watch for Ghidra function splits: a builder whose listing ends without
an epilogue continues in the next "function" (BuildUniversityDialogShell = 4 fragments).
## 37. A bead's "not ported yet" claim can be two independent recoveries of the
    same class under different names — check GetRuntimeClass address identity

`bd 1uj.6` asked to port "TMilitaryUnit::CreateObject/GetRuntimeClass at
0x5c2cb0/0x5c2dd0" onto the existing `include/game/TMilitaryUnit.h` (a raw-pad,
`TObject`-direct, no-vtable field/getter surface model). Trap: a *different*
class, `TMilitaryUnitOrderState` (vtable 0x66eea8, real `TUnit`-derived ctor at
0x5c2df0, real CString member, already at ~86%), turned out to be the SAME
game class, independently recovered by an earlier session under a different
Ghidra-guessed name. The tell: `TMilitaryUnitOrderState::GetRuntimeClass`'s
body at 0x5c2dd0 (`mov eax, 0x66ed70; ret`) is the address the RTTI oracle
lists as **TMilitaryUnit**'s `getrtc` — an exact address match, not a
name/vibes match. Corroborating: the "TMilitaryUnit-only" getters
(`GetUnitMovementClassId` etc., 0x5c34xx) read `[ecx+4]`/`[ecx+6]`, which are
exactly `TUnit::orderType`/`field_6` — fields already owned by the *other*
class's base. And the old model's "unmodeled pad regions" (0x08-0x13,
0x1c-0x23, 0x28-0x33, 0x3a-0x3f) decomposed exactly into the inherited `TUnit`
fields plus the other class's own already-recovered fields — a strong signal
that "recover these 4 pad regions" was actually "notice these two classes are
one class." **Always check whether a `GetRuntimeClass`/`CreateObject` address
already belongs to a *different* manual class before porting it onto the bead's
named target** — `config/rtti_class_oracle.csv`'s descriptor-address column
(e.g. `0x66ed40`/`0x66ed58`/`0x66ed70`) is the `CRuntimeClass` struct address
(named `class<X>` by the `IMPLEMENT_RUNTIMECLASS` macro), **not** the vtable
address; don't assume a bead's "vtable at 0xNNNN" phrase is literally the
vtable — verify via `just ghidra-listing` on the ctor. Fix was a straight
merge: keep the better-evidenced class (real ctor/vtable/CString), add the
other's fields/getters via the inherited base, delete the duplicate file,
`sed`-rename call sites, `just regen-stubs` (auto-relocates ownership rows +
picks up new `// SYNTHETIC` claims), rename the scalar-deleting-dtor's curated
`symbols.csv` backtick name to match (Hard Rule 10) — that was the only vtable
slot mismatch after the merge. One MSVC500 TU-wide ripple regressed two
unrelated functions in the touched files by small amounts (register/operand
reordering, not logic) — accepted as residual risk per the TU-codegen-
fragility pattern (note 12b / TGreatPower notes) since the aggregate stats
were net positive and the field rename was unavoidable.

## 38. Widening a marked function's signature can "unpair" it — suspect a comment between `// FUNCTION:` and the decl before COMDAT-folding

Symptom after changing a `// FUNCTION:`-marked function's *signature* (e.g.
0-arg stub → real 2-arg body): `just compare 0xADDR` flips from a normal score
to **"Failed to find a match at address 0xADDR"**, and every vtable that
references that slot drops ~2% (one slot of ~49 ≈ 2.04%). It's tempting to
diagnose this as COMDAT/ICF folding (two identical bodies collapsing to one
address). **Check the marker placement first — it's almost always Hard Rule 3.**

When you add an explanatory comment you may naturally write it *between* the
marker and the declaration:

    // FUNCTION: IMPERIALISM 0x00488c50
    // Read a length-prefixed shared string…        <-- breaks the association
    void TStream::streamSlot70(CString* dest, int maxLen) { … }

reccmp's parser requires the `// FUNCTION:` line to be *immediately* followed by
the declaration; any intervening comment/blank line detaches the marker, so the
recomp symbol never pairs to the original address → "Failed to find a match",
and the now-unresolved vtable slot pointer mismatches. Fix: move the prose
*above* the marker:

    // Read a length-prefixed shared string…
    // FUNCTION: IMPERIALISM 0x00488c50
    void TStream::streamSlot70(CString* dest, int maxLen) { … }

Confirm it's not folding by dumping the recomp symbol addresses
(`reccmp.cvdump.Cvdump(pdb).symbols().run()` → each function has a unique
`(section, offset)`); if the addresses are distinct, it was never a fold.
`just marker-gate` catches this too, but a bare `just compare`/`just stats` will
not — the "unpaired + all vtables referencing that slot lose ~2%" fingerprint is
the fast tell. (Seen porting `TStream::streamSlot70`, bd 1uj.56: base +
TFileStream override both went 0.00% → 100% once the marker sat directly on the
decl.)

## 39. Library vtable addresses need a decorated-symbol row, or every dtor pays

A statically-linked MFC vtable address (e.g. CObject's `??_7CObject@@6B@` at
0x66fec4) that only has a name-typed `global` row in `config/symbols.csv` classifies
the original-side reloc as DATA while the recomp side is VTABLE — reccmp then counts
a diff line in *every* destructor that stores it (the ubiquitous
`mov [ecx], offset CObject::vftable` tail of inlined base dtors). Fix: give the csv
row the decorated symbol (`66fec4|CObject::`vftable'|??_7CObject@@6B@||global||`) so
`match_symbols` pairs it exactly. One such row change took `TViewMgr::~TViewMgr`
50%→100% and improved ~50 functions in the same pass. Corollary from the same
session: a fully-optimized derived dtor can compile to a *single* store of the
root-base vtable + `ret` (all intermediate vptr stores dead-store-eliminated), so a
7-byte "SetXxxBaseVtable" junk-named function called only from a scalar deleting
destructor is that class's real `~T()` — claim it with a companion `// SYNTHETIC:`
block, never model it as a vtable-reset helper.

## 40. Two cheap recomp-side diffs to sweep in the near-miss (98–99%) band

Both surface as a *recomp-only* line in `just compare 0xADDR` (green `+`) with no
matching original line, and both are one-line source fixes on already-owned bodies —
no marker/ownership churn, so skip `regen-stubs`.

- **Trailing `+xor al,al` = a Ghidra `undefined` placeholder return that is really
  `void`.** A body written `undefined Foo() { …; return 0; }` makes MSVC emit
  `xor al,al` before the epilogue; the original returns void and emits nothing. Retype
  the decl **and** the definition to `void` and drop `return 0;`. `undefined` is the
  1-byte placeholder, so this is always `xor al,al` (a 4-byte `int` return would be
  `xor eax,eax`, e.g. `0x5e5140` where the original *does* `xor eax,eax` and the fix is
  the opposite direction — retype to `int`+`return 0`). Swept 7 of these (TDisplayMgr
  ×3, TMacViewMgr atlas ×4) 94–98%→100% in one build. These are frequently *virtuals*
  in a "GENERATED DECLS" header block introduced by that class (no base/override to
  keep in lockstep) — changing the return type there is self-contained; the formatter
  re-aligns the trailing `// slot` comments, so run `just format` after.
- **Recomp-extra `test rX,rX; je …` = a null guard the original never had.** When the
  original loads a pointer and immediately dereferences it (`mov eax,[ecx]; call
  [eax+off]`) but the port wraps the call in `if (p != nullptr)`, reccmp shows the
  `test/je` as recomp-only (and a downstream `je` displacement shifts by the extra
  bytes). The original author knew the pointer was non-null here — delete the guard and
  call unconditionally. (`TInvadeMission::RefreshSlot40` 0x53f7d0,
  `TNumberText::ShallowClone` 0x4912b0, both →100%.)

## 41. The pre-v9-save branch dispatches a *different* vtable slot — read the byte offset

reccmp `call [eax+0xNN]` vs `call [eax+0xMM]` on an otherwise-identical body means the
source calls the wrong virtual. Map byte-offset → named method with slot_index =
byteOff/4 and the header's `// slot 0xIDX` comments (repo convention even names them by
offset, e.g. `Call30` = slot byte 0x30, `RefreshSlot40` = byte 0x40). Fix is swapping
the method name at the callsite, no signature change. (`TMission::ReadFrom` 0x5358a0
called `RefreshSlot40()` where the original dispatches slot 0x30 `Call30()`, 98%→100%.)

## 42. Extractor over-extends a class vtable to swallow adjacent one-slot vtables

The generated `// slot 0xNN … 0xADDR` block appends every non-NULL pointer up to the
next *known* vtable, so a class whose real table is followed in memory by small (often
1-slot) `stretch<T>`/helper vtables gets those foreign slots mis-attributed as its own.
Tell: a run of NULL slots (the real table's abstract tail) and then 1–2 more non-NULL
"slots" whose target functions operate on a *different* `this* ` shape than the class
(e.g. touch only `[ecx+4/8/c]` = a stretch data/capacity/count header, not the class's
0x2a8-byte layout). Confirm by resolving the slot pointer (`just ghidra-vtable-dump
Name 0xVTABLE --count N` → follow the ILT `JMP`) and checking whether any *global* sets
its vfptr to that slot's byte address (that global is the real owner). Fix: move the
`// FUNCTION:` markers off the host class onto a real concrete subclass of the helper
template, rename the `symbols.csv` rows, and leave the helper vtables unannotated when
their address overlaps the host's vtable DATA region (pair the methods by address
marker, not `// VTABLE:`, to avoid the collision gate). This turned the two empty
`TMapMaker::SetEnabled/SetState` stubs (0x52a760/0x52c0a0) — actually
`SeaSegmentStretch/SeapointStretch::GetOrAppendUnique` (the by-value append) — from
0–9% into 93%/91%. Corollary: a `stretch<T>` element size is read straight off the grow
strides (double `n*0x30`/fallback `n*0x18` ⇒ 0x18 element; `n*0x20`/`n*0x10` ⇒ 0x10),
and a by-value append copies exactly `sizeof/4` dwords (6-iter `rep movsd` = 0x18,
4 unrolled movs = 0x10) — the copy width is independent structural evidence for the type.

## 43. stretch<T> vs MFC CArray: realloc-double-or-fallback is the discriminator

Both are growable arrays with a `data/capacity/count` tail, but MFC `CArray` grows by
allocating a fresh block and *copy-constructing* elements across (new + copy + delete),
whereas the project's `stretch<T>` family reallocs in place — request `count*2*stride`
via `ReallocateHeapBlockWithAllocatorTracking`, and on failure realloc to the exact
`count*stride`. If you see that realloc-double-then-exact-fallback shape (no element
copy loop on grow), it is a `stretch<T>`, not a `CArray`; model it as a real
`class X : public stretch<T, Tag>` overriding the single-slot append virtual, not an
ad-hoc struct. Mac CodeWarrior evidence names the family `stretch<Seapoint>` /
`stretch<SeaSegment>` with `Add/operator[]/OverStretch` members.

## 44. All globals belong in global_data_tables — never architect around commutative-FP noise

**Globals go in `global_data_tables.{h,cpp}`.** Declare every shared global (`extern` +
forward-decl if needed) in `global_data_tables.h` and define it in `global_data_tables.cpp` —
including plain, non-reccmp-tracked subsystem scratch tables (e.g. the overlay
Seapoint/SeaSegment stretch tables and the hex-offset tables). Do **not** stash a global in a
subsystem `.cpp` with `.cpp`-local `extern`s to keep a widely-included header byte-identical.

That was an earlier (wrong) reaction to a phantom: adding declarations to `global_data_tables.h`
recompiles the float-heavy TUs and the TGreatPower commutative-FADD stubs
(0x4e0590/0x4e05d0/0x4e0610/0x4e0650/0x4e0690, `fld [tblA]; fadd [tblB]`) swap their two
source-table operands, so reccmp reports 100%→43%. **That "regression" is meaningless.** `a+b`
== `b+a`; the code is semantically identical and the operand order is pure compiler scheduling
noise the source cannot steer. Ignore these flips — do not revert real structure, relocate
globals, or otherwise contort the design to preserve the phantom 100%. Accept the delta and run
`just stats-baseline-update`. The same applies to sub-1pp register-allocation wobbles in
neighbouring functions when you add code to a TU: noise, not regressions.

Corollary: reccmp's per-function % is a matching *aid*, not a score to defend. A drop caused by
commutative FP operand order, register allocation, or instruction scheduling in code you did not
change is not a regression worth a single line of work.

## 45. Big matching-heavy function: use float (not double) locals to avoid an alien frame

Real, source-steerable yield on the 1073-byte `BuildOverlaySpanRecordsFromQuadBorderLinks`
(0x52cae0): a `double` local for a distance forces an 8-byte-aligned frame (`push ebp;
and esp,-8`) the original (which used `float`) never emits — storing the metric as `float` /
comparing straight off the FPU return removed the whole alien prologue. Match the original's FP
width. Beyond that, a big function's score is dominated by the compiler's induction-variable
register choice (ebx vs the original's ebp) which source can't steer — expect ~30% structural
and treat the absolute aligned-byte gain (≈320 here) as the win, not the percentage. (A large
standalone function may live in its own `.cpp`, following the merge-function precedent, for
organization — but never move code between TUs to chase neighbouring register-allocation noise;
see note 44.)

## 46. Thunk-only-caller thiscall methods are frequently mis-attributed — reattribute by `[this+off]` field layout, not the curated name

When a `__thiscall` method's *only* xref is an ILT thunk (`JMP 0xADDR`), Ghidra/symbols.csv
guessed its owning class from weak evidence, so the `ClassName::` prefix is unreliable
(Hard Rule 6 — names are provisional). Recover the real receiver from the object-field
accesses in the body: match each `[this+off]` against candidate classes' recovered layouts.

Concrete wins (this session, the civilian-order cluster all mislabeled `TCivToolbar::`):
- `CanAssignCivilianOrderToTile` (0x4d2f60): `[this+4]` is used as a `TCivUnit*` selected
  entry → matches `TCivMgr::selectedEntry` (0x4) exactly → real owner is **TCivMgr**
  (TObject-derived), not the TControl-derived toolbar. The compat lookup is on a *global*
  (`g_pDiplomacyTurnStateManager`, 0x6a43d0), not `this`, so "this calls a TControl method"
  is NOT evidence the receiver is a TControl.
- `CalculateDeveloperTilePurchaseCost` (0x518b40): `this->field0c` is a stride-0x24 tile
  table base → matches `TMapMgr::terrainStateTable` (+0xc, `TTerrainStateRecordView[]`) →
  real owner is **TMapMgr**. (Still blocked on a slot-0x13 vtable dispatch on the
  ambiguously-typed `g_pNationInteractionStateManager` — TTradeMgr vs TDealList.)

Procedure: (1) list the `[this+off]` accesses; (2) `grep` recovered class headers for a
field at that offset with a compatible type; (3) reattribute — update the symbols.csv name,
move the marker to the real class's `.cpp`, declare on its header. Reccmp pairs by address,
so reattribution never risks the score; it just unlocks typed field/virtual access
(`this->selectedEntry`, `g_apTerrainTypeDescriptorTable[c]->IsEncodedNationSlotMinus200Equal(...)`).
The residual on these is usually pure register allocation (original caches `this`/param in
edi/cx; the rebuild keeps them in ecx/dx) — same instructions, don't chase (Hard Rule 12).

## 47. Detangling a two-class "frankenclass": split by vtable, recover layout from accessor displacement

When Ghidra (or an earlier port) merges two classes into one — e.g. a manager and a small
list class conflated because one *contains* the other — the tell is a single class carrying
**two distinct `// VTABLE:` roles** and methods that match only 6–60% because their
`this + off` accesses assume the wrong base. `TTradeMgr` (vtable 0x66d990, `: TObject`, size
0xaf0) had been bolted onto `TDealList` (vtable 0x66da38, `: TSortedPtrList`, size 0x18); the
edge was **composition** — `TTradeMgr::categoryRankLists[]` holds real `TDealList` instances
(its InitializeDefaults `new`s them and installs 0x66da38 into each).

Split procedure that keeps both halves green:
1. **Recover the real field layout from the accessors' disassembly, not the decompile.** A
   one-line getter `MOVSX EAX,word[ESP+4]; LEA EAX,[EAX+EAX*4]; SHL EAX,5; MOV AX,[EAX+ECX+0x18]`
   reads *exactly*: stride `5<<5 = 0xa0`, field displacement `0x18`, array base folded in.
   Since MSVC folds `array_base_offset + field_offset` into one displacement, place the member
   array right after the vptr (offset 0x04) and shift the struct field offsets down by 4
   (here 0x18 → struct 0x14, 0x0a → struct 0x06) so codegen reproduces the same displacement.
   Cross-check against the ctor/init loop's cursor deltas (`LEA ESI,[ECX+0x0e]`, `ADD ESI,0xa0`,
   `LEA EBP,[ECX+0xaa8]`) and the object size to pin every array offset — the layout arithmetic
   must total the RTTI size exactly (0x04 + 0x11*0xa0 = 0xaa4, pad, ranks[0x11] at 0xaa8 → 0xaf0).
2. **Own every primary-vtable slot on the new class** (overrides of the base slots + all
   introduced virtuals in slot order) so the compiler lays the vtable out correctly — honest
   `return 0;` bodies are fine, slot correctness is body-independent, and `just vtable NewClass`
   goes 100% immediately even with unfinished bodies. Move the already-ported real methods with
   their markers; promote the autogen stubs (verify none are called by name first).
3. **Retype the global + repoint the alias header**; move its definition (with the `// GLOBAL:`
   marker) into `global_data_tables.cpp` (the marker gate rejects `// GLOBAL:` anywhere else).
4. Getter param width matters: `MOVSX word` ⇒ `short` param (not `int`) — fixing both the
   offset and the width took the accessors 60→100% / 37→64%. Callers that now truncate an int
   arg may dip a couple pp; accept it (correct model > local caller score, Hard Rule 12).
Residual on the trivial ctor (just a vtable write in the original) stays low because the
out-of-line empty `TObject::TObject()` base ctor isn't inlined under /Ob1 — systemic, not a
detangle defect.
