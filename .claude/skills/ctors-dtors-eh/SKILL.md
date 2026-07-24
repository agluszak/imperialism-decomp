---
name: ctors-dtors-eh
description: Match constructors, destructors, and exception-handling codegen in the Imperialism decomp — EH frames (push -1 / __ehhandler / fs:[0]), EH state numbers, non-POD locals forcing single-epilogue shapes, member-init order, inlined base ctors, scalar deleting destructors, new-expression null checks. Load whenever a target has an EH prologue, CString/collection locals, constructs or destroys objects, or looks "too complex because of EH" — EH-heavy functions are ported now, never postponed; the EH scaffolding is compiler output that appears when the C++ shape is right.
---

# Constructors, destructors, and EH

EH scaffolding is never hand-written: the `push -1; push __ehhandler_...;
mov eax, fs:[0]; push eax` prologue, the `mov dword ptr [esp+N], <state>` stores, and
the unwind funclets all fall out of declaring the right locals/members and using real
`new`/ctors. If the EH shape mismatches, your OBJECT MODEL is wrong — fix the types,
not the frame.

## EH quick facts

- **One EH state per constructed thing.** Each non-POD local (CString, iterator,
  collection) and each `new`-expression bumps the state counter. Extra `{ }` scopes
  shift state numbers and score WORSE — match the original's scope structure.
- **`new T()` emits `push sizeof(T); call operator new; test eax,eax; je skip; call
  ctor` with an EH temp state (-1 after).** Never null-check after `new` in source —
  the compiler's own check is the one you see. MFC `operator new` (0x606f73) is a
  LIBRARY symbol.
- **A local object with a non-trivial dtor forces MSVC's single-epilogue shape**: all
  returns funnel through one exit that runs the dtor. Early returns in source are
  fine — the compiler rewrites them; don't contort control flow to imitate the merge.
- **Scalar deleting destructors (`??_G`) are compiler-generated** — claim with
  `// SYNTHETIC:` + mangled name in symbols.csv, never hand-write (construction Hard
  Rule 10).
- **Member-init placement**: use init lists in declaration order when the original
  writes scalars before member ctors; body assignments force members first
  (construction Hard Rule 3). POD-only ctors are the exception — see field note below.

## Field notes

### Constructor matching = field-init PLACEMENT
*(ex decomp-loop note 3)*


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

### Scalar deleting destructors
*(ex decomp-loop note 8)*


Compiler-generated `??_G`/`??_E` scalar deleting destructors must be SYNTHETIC, never
hand-written. Make the class polymorphic, the ordinary dtor implicit, and claim the
address with a `// SYNTHETIC` marker + exact backtick name in `symbols.csv`. Full
recipe in **AGENTS.md construction Hard Rule 10** and [[synthetic-scalar-deleting-dtor]];
remaining candidates in [[next-scalar-dtor-rollout]].

- A no-op custom `operator delete` lowers the `??_G` match — prefer the real global
  delete unless the class genuinely overrides new/delete (`0x534740` 58.8%→81.8%).
- A `Destruct*AndMaybeFree` **name** is not proof of a destructor — read the body
  (false positives: `0x58f1a0`, `0x4a0190` are hit-test/render functions).

### Destructor placement follows original emission, not source-style preference

Moving `~T()` between a header and `.cpp` changes VC5 inlining and COMDAT folding across
callers, derived destructors, scalar deleting destructors, and vtables. Classify it first:

- no standalone ordinary body and member/base teardown is sufficient: keep it implicit;
- standalone original ordinary-destructor address: out-of-line definition with a FUNCTION
  marker in the owning `.cpp`;
- body expanded at listing-proven retail call sites: inline in the header, after checking
  more than one caller when the class is shared;
- vtable proven to have no destructor slot: a non-virtual destructor is valid, but delete
  only through the exact concrete type.

Never add or relocate an empty ordinary destructor merely to emit or claim `??_G`; that
body stays compiler-generated and SYNTHETIC. After a visibility change, compare the real
ordinary destructor (if any) and run `just vtable` for the class plus affected siblings.
The full policy is in `docs/reference/construction.md`.

### A local object with a non-trivial dtor forces MSVC's single-epilogue shape
*(ex decomp-loop note 33)*


A function-scope local with a destructor (e.g. `CString`) that the original constructs
*unconditionally right after the prologue* forces every exit path through **one shared
epilogue block** running the dtor, with early exits becoming `jmp`s to it. Scoping that
local inside one branch (naive "where is it used" reading) gives each exit its own
duplicated epilogue and decorrelates nearly every jump offset. Diagnostic: compare the
recomp's `call CString::CString` position against the original's first few bytes — if
the original constructs at entry, hoist the local to function scope even if only one
switch case reads it. Evidence: 0x57da70, hoisting one `CString` shrank the byte-size
gap from +62 to +1.

### GlobalHandle/GlobalUnlock/GlobalFree pairs = windowsx.h GlobalFreePtr; paired free-blocks + EH state = a local descriptor class with inlined dtor
*(ex decomp-loop note 41)*


The repeated triple `GlobalUnlock(GlobalHandle(p)); GlobalFree(GlobalHandle(p))` is
the windowsx.h `GlobalFreePtr(p)` macro (vendored header has it) — write the macro,
not hand-rolled pairs. When a function with no visible C++ objects still carries an EH
frame whose unwind funclet frees a group of stack slots this way, those slots are a
real local class (ctor zeroes the fields, dtor runs the GlobalFreePtr pairs): model it
as a small stack descriptor class with inline ctor/dtor and the EH states fall out
naturally (WaveLoadDescriptor in TSoundResourceManager, 0x49c290/0x49c430).

- **Verify shared-class inline ctors against multiple original call sites before
    zero-initializing members.** CIterator's ctor stores ONLY ownerList in the binary
    (Reset() seeds nextPosition/current); our all-member init-list added two dead
    stores at every use site repo-wide. Fixing the ctor to match took several
    functions to 100% in one stroke (0x5a53e0, 0x59f890, 0x5c38e0). When a repeated
    small diff (same extra stores) appears across many functions using one helper
    class, suspect the helper's ctor/layout, not the functions.

  *(ex decomp-loop list-note 61)*

- **A `Ghidra_name::WrapperFor_Construct<Class>BaseState_At0x...` that installs a
    *different* class's vtable (`this->vftable = &TOtherClass::_vftable_`) and/or writes
    `this[1].vftable` (past the object) is a COMDAT-folded construction fragment, not a
    real per-class ctor.** The linker folded several classes' identical construction tails
    into one address and Ghidra attributed it to whichever symbol it found first. Do NOT
    hand-port it as a fake per-class ctor (it would force a manual foreign-vtable write,
    violating construction Hard Rule 2). Leave it as a stub. Tell-tales: the `WrapperFor_`
    prefix, an installed vtable whose class name ≠ the `this` class, and tiny size.

  *(ex decomp-loop list-note 71)*

- **A base ctor that the compiler *always inlines* (no standalone out-of-line address —
    it appears only inside CreateObject and derived ctors) still gets a real C++ ctor
    body, just no `// FUNCTION:` marker.** Give it `: Base() { field = ...; }` so derived
    `: ThatBase()` chains construct correctly, and note in a comment that it is markerless
    because always-inlined (e.g. TPanelView). reccmp never pairs it (recomp-only, no
    marker), and derived ctors that call it score the usual accepted inlining-divergence
    band (80-86%) rather than 100%. This is the base half of the recurring ctor-inlining
    pattern: the real out-of-line base call our source emits vs. the original's inlined body.

  *(ex decomp-loop list-note 72)*

- **A trivial derived ctor can hard-fail reccmp pairing ("Failed to find a match at
    0xADDR") even when its same-shaped siblings pair fine** — our toolchain sometimes emits
    no uniquely-pairable out-of-line copy for one `: Base() { oneField = 0; }` ctor while
    emitting them for its siblings. Per the TNextMoveCommand precedent, revert just that
    marker (restore the markerless `{}` body) rather than faking it, AND manually delete
    the stale claim — the source-index duplicate check reports
    "Pruned ... 0" and does not auto-remove it; the stub count only rises back after the
    manual delete + re-regen.

  *(ex decomp-loop list-note 73)*

### A scalar-deleting-destructor stuck below 100% often means the real dtor is mislabeled
*(ex decomp-loop note 101)*


When a `??_G` scalar deleting destructor won't reach 100% and the only diff is its *call
target* name (`just compare` shows orig calling `SomeGhidraPlaceholder` where recomp calls
`~Class`), the placeholder IS the real virtual destructor. The scalar deleting destructor's
one non-trivial instruction is `call <destructor>`; reccmp resolves the orig call target to
whatever name owns that address, so a Ghidra placeholder there surfaces as a name mismatch.

Fix: identify the address (grep the placeholder name → symbols.csv/index.csv), confirm it is
a trivial destructor (`just ghidra decompile` shows a ~7-byte `this->vftable = &PTR_...;
return;`), then (1) add `// FUNCTION: IMPERIALISM 0xADDR` to the manual `~Class()` body,
(2) rename the symbols.csv row `ADDR|Class::~Class|??1Class@@UAE@XZ|...`, (3) give the scalar
deleting destructor its own `??_GClass@@UAEPAXI@Z` mangled name in the same file, (4)
rebuild to drop the placeholder stub and claim the address. TTacticalPlayer's dtor
at 0x59ae60 masqueraded as `CreateTTacticalPlayerInstance`; claiming it took both the dtor and
its scalar-deleting sibling to 100% (+2 aligned).

### Inlined virtual base destructor: watch for COMDAT-fold collateral
*(ex decomp-loop note 106)*


A derived dtor in the original often *inlines* the base dtor's tail (set base vptr → base
cleanup → chain to the library base dtor). To make ONE derived dtor inline-match, it is
tempting to move the base dtor's body `inline` into the header so it's visible in the derived
TU. **Do not do this reflexively.** When the base has many member-less leaf subclasses, an
inline base dtor makes their compiler-generated (real) destructors byte-identical, the linker
COMDAT-folds them, and the *scalar-deleting-destructor addresses in their vtables shift* — every
folded sibling's `` `vftable' `` drops from 100% (one slot now points at a folded address that
reccmp pairs to another class's dtor). Net for TModalDialogBase: +2 (two dtors reach 100%) but
−15 aligned (≈10 sibling vtables + some folded no-op leaves). **Keep the base dtor out-of-line**
and accept that the one derived dtor stays ~83% (it emits a `call` to the base dtor instead of
inlining it). A single +100% is never worth breaking 10 sibling vtables. Diagnose which funcs
regressed by diffing `config/baselines/reccmp_progress_baseline.functions.csv`
against a fresh `reccmp-reccmp --json` capture — aggregate stats alone won't tell you WHAT fell.

### POD-only constructors: body assignments in observed store order, not init lists
*(ex decomp-loop note 109)*


For a constructor whose members are ALL POD (pointers/ints/shorts/bytes, no sub-objects), MSVC
emits the field stores in SOURCE order and sets the vptr first. A member-initializer list runs
in DECLARATION order and often mismatches the original's store order (it stored 0x78/0xd0 before
0x68, i.e. not declaration order) — and `-Wreorder` forces the list back to declaration order
anyway. So mirror the original with body assignments in the exact observed store order; the
vptr write lands first automatically. Took the TTacticalBattleView ctor 78.9%→100%. (This is
the flip side of construction Hard Rule 3, which mandates init lists ONLY when a scalar must be
set before a later NON-POD member is constructed.)

### Trivial-ctor factories: define the empty ctor inline in the header
*(ex decomp-loop note 116)*


When a small factory (`new T()` + second-phase init call) scores badly and its diff shows
`CALL <base ctor thunk>` + `MOV [reg], offset vftable` where the recompile has one `CALL
T::T`, the original defined `T::T()` inline in the class (MSVC500 /Ob1 expands it at every
`new` site as: out-of-line BASE ctor call + own vptr store). Fix: move the empty ctor
definition into the header (`T() {}` in-class) and delete the .cpp definition (it carries
no FUNCTION marker when no standalone copy exists in the binary). This took the
TTechItemLine::CreateLineItemView factory (0x5b1160) from 41.6% to 100% in one edit. The
same applies transitively: a ctor whose INLINE expansion at call sites shows the
grandparent ctor call means the parent's ctor is header-inline too. Caveat: if a
standalone copy of the ctor DOES exist at an address (it has a FUNCTION marker), making it
header-inline changes where the out-of-line copy is emitted — check `just compare` on the
marked address after the move.

### Mac-style two-phase construction: `Construct*BaseState` are methods, not ctors
*(ex decomp-loop note 117)*


In this binary the `Construct<Class>BaseState` functions (TTEView 0x486050, TDeluxeText
0x5b5ff0, TTechItemView 0x5b12e0) are NOT constructors: none stores a vptr; each is called
explicitly after `new T()` (the MacApp IViewClass second-phase-init idiom). Port them as
plain member methods with the real arg lists (dead filler args included — `RET 0x2c` = 11
args even if three are never read), and port the callers as `T* p = new T(); p->Construct...
(args)`. Do not fold them into the C++ ctor: the original ctor is the separate trivial
inline (note 116), and merging them mismatches both.

- **Claiming a small "Construct<Class>BaseState" ctor stub is a marker-only win ONLY when
    the ctor is already defined out-of-line in a .cpp; moving a header-inline ctor into a
    .cpp to attach the marker regresses every call site that inlined it.** These 18-byte
    stubs (e.g. 0x534870 TIndexAndRankList, 0x5b6a00 TNoHiliteText, 0x5a6560 TNextMoveCommand)
    are the compiler's out-of-line COMDAT copy of `T::T() : Base() {}` — base ctor call +
    vtable install + `mov eax,ecx` return-this. If the class's ctor already lives in the .cpp
    as `T::T() {}` (TNoHiliteText, TIndexAndRankList), just add `// FUNCTION: 0x...` above it
    — the body already emits the right code. BUT if the ctor is header-inline
    (`T() : Base() {}` in the .h, as TNextMoveCommand was), MSVC inlines it into every
    `new T()` / DYNCREATE CreateObject site, and those matched 100% *because* the original
    inlined it there too. Moving it out-of-line to attach the marker flipped
    TNextMoveCommand::CreateObject 100%->49% and a `new TNextMoveCommand()` caller 100%->82%
    while gaining only the one out-of-line copy — a net loss. Keep header-inline ctors inline;
    only claim the marker on ctors already out-of-line. Also: a `T : TSortedPtrList`/deep base
    ctor may cap at ~86% (0x534870) because the original inlines the intermediate base ctor
    (calls CPtrArray() directly) while the out-of-line recompile calls TSortedPtrList() — the
    accepted cross-TU base-ctor-inlining residual (same shape as note on TEscortMission).
    Always re-check `just stats` delta and diff the report for offsetting drops after a
    ctor-marker change, since the aligned count can stay flat while hiding a swap.

  *(ex decomp-loop list-note 102)*

- **An inlined-ctor `new` site whose field stores are NOT in declaration order (and whose
     vptr store lands last) is a body-assignment ctor, not a member-init list.** Write the
     header-inline ctor with body assignments in the observed store order (TSoundChannelNode:
     0xc,0x10,0x8,0x4,0x14,0x18). If no standalone ctor symbol exists in the binary, the ctor
     must be defined inline in the header or every `new T()` site emits a call that the orig
     doesn't have. The vptr-store position (recomp first, orig last) is compiler-internal and
     costs ~2 lines — accept it.

  *(ex decomp-loop list-note 110)*

### Scalar-dtor call chains end in incremental-link islands — claim the island, never re-home
*(2026-07-23, bd qmhn)*

The retail exe is an **incremental LINK 5.0 image**: a ??_G's `call` typically chains
`ILT thunk -> stale 5-byte jmp island (+ nop padding) -> ILT thunk -> real body`, and the
linker folded/aliased dozens of leaf-class destructor symbols into a few shared base
bodies (many leaf views end at TView::~TView 0x48a9d0; TBook/TPageCorner at TPicture's
0x48f250). The island at the class's old address IS the symbol's canonical location:
claim it with the class's own `~C()` marker (`just add-destructor-markers`). reccmp's
thunk-chasing stops at the first *named* node, so the island claim is exactly what makes
the ??_G caller's `call` operand pair per class (90.91% -> 100%). Do NOT "fix" these
claims by moving them to the chain's final body — the final is shared and already claimed
by the base class, so re-homing removes the per-class name and drops the ??_G back to
90.91%. Corollary: the stale islands encode the original developers' relink history, so
no clean re-link (ours or theirs) can ever reproduce them; per-function pairing with
named island claims is the attainable maximum.

*(Update 2026-07-24, bd 5jjn)*: island rows no longer cost anything. Every island is a
`folded_symbol_group` row in `config/template_aliases.csv` (discover new ones with
`just stale-jmp-islands --emit`; `just template-alias-check` re-proves the chain), and
reccmp consumes those groups: a claimed island row scores as an EFFECTIVE match
(reason `folded_symbol_alias`), call/jmp operands into any group member pair with the
canonical, and folded vtable slots pair through the group. When claiming a new island,
add its `folded_symbol_group` row in the same change so it scores effective immediately.
