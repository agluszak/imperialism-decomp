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

