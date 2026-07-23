# Field notes (class-recovery)

Accumulated matching lessons for this skill's domain (migrated from the old
decomp-loop heuristics file; append new ones here).

### Class recovery discipline
*(ex decomp-loop note 9)*


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

### Embedded subobject → expose via its real type
*(ex decomp-loop note 16)*


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

### Two independent recoveries of one class can hide behind different names — check GetRuntimeClass address identity
*(ex decomp-loop note 37)*


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

### Detangling a two-class "frankenclass": split by vtable, recover layout from accessor displacement
*(ex decomp-loop note 50)*


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

- **Verify stub attribution by field-access consistency with ported siblings, NOT Ghidra's
    `this`-type label or symbols.csv class prefix -- the remaining stub pool is heavily
    mis-attributed.** A scout sweep of small stubs turned up candidate after candidate whose
    Ghidra `this` type / curated name was contradicted by the disassembly: 0x598840
    ("TToolBarCluster") reads `[ecx+0x94]` = TMapUberPicture's `invalidationFlag94` and calls
    a thiscall on the unrecovered `goodGoldTagControlA4` (a call the codebase deliberately
    left unmodeled); 0x4e8b50 ("TAttackProvinceMission", ASSERT_SIZE 0x34) writes
    `[this+0x970]` -- impossible for a 0x34-byte class; 0x4b6a30 ("TTrainingOrder") does
    `ADD word [ecx+8]` where the real layout has a `TCity*` pointer at +8. The reliable
    signal that a stub is a clean port target: (i) its address sits BETWEEN two already-owned
    methods of class C, AND (ii) its disassembly reads only C's own confirmed field offsets
    and dispatches C's own helpers -- then it is a C method regardless of the label. That is
    how the 0x5549a0/0x554a30/0x554a80 TTaskForce trio was confirmed (all read
    `childOrderList`@0x10 + `g_NavyOrderResourceDescriptorTable`, sit among ported TTaskForce
    siblings). Corollary red flags that a "clean" target is actually entangled: an opaque
    param whose only use is `*(char*)p` but whose concrete type isn't modeled, a
    partial-register arg load (`mov ax,[mem]; push eax` rather than `movsx`) that clean C++
    won't reproduce, or a field used with semantics that contradict its recovered name
    (required_count passed as a diplomacy `sourceNation`). Skip those rather than mis-model.

  *(ex decomp-loop list-note 87)*

- **`new T()` callsites are an authoritative sizeof(T) oracle — use them to catch
    under-modeled classes.** A `push 0xNN; call 0x606f73` (MFC `operator new`) at a
    `new T()` site pins `sizeof(T)` exactly, and structured reccmp diagnosis flags a
    trusted wrong size as `immediate_value` (`0x80` vs `0x64` = class is 0x1C bytes
    short, not codegen wobble). An `inconclusive` raw push difference is not equivalent
    evidence. Worked example: `TGreatPower::ReadFrom` (0x4d92e0)
    builds three ministers with `push 0x80` / `push 0x1c4` / `push 0x94`; the recomp
    pushed 0x64/0x2c/0x2c, exposing that the shared `TMinister` base was 0x2C instead
    of its real 0x48. Fix belongs on the *base* when the whole family is short: derived
    ministers each begin their own state at 0x48 (ConstructTForeignMinister @ 0x52f070
    first writes [this+0x48]), and a header whose trailing array reads `state48[0x80 -
    0x48]` already assumes base 0x48 — so growing the base (`pad2a[0x48-0x2A]`) fixes
    every derived size at once with no field shift (derived classes had no modeled
    members). Don't size-clamp a class that derives through an intermediate you haven't
    sized (TCityInteriorMinister via TInteriorMinister): you can't attribute the
    0x48..total region across the chain without each level's own `new` size — defer to
    real class recovery.

  *(ex decomp-loop list-note 88)*

### A baseless, vtable-less game class is a red flag: disguise-or-find-the-vtable
*(ex decomp-loop note 103)*


In this codebase virtually everything descends from `CObject`/`TObject`, so a `class TFoo {`
with no base, no `// VTABLE:`, and a leading `pad_00[4]` (or `field0` = 0) deserves a check —
it is usually one of: (a) a **disguise** of a real polymorphic class that should be merged, or
(b) genuinely polymorphic with an **unfound vtable**, or (c) a genuine non-poly data manager
whose vtable(s) belong to **members it holds**, not itself.

Decision procedure (all from Ghidra, fast):
1. `just ghidra xrefs 0xMETHOD` on the class's method. If the xref is `from 0xNNNN [DATA
   address-taken]` in the vtable region, the method is a **virtual slot** → the object is
   polymorphic. Then find the owning vtable: list the neighbours of the method address in
   symbols.csv (functions in the same 0xNNNxxx TU) and match a nearby `// VTABLE:` base
   (`base + slot*4 == the DATA address`). That base's class is the real owner → **merge the
   phantom into it.** (TCityRecruitmentOrderContext's one method was TUnitOrder vtable slot
   0x0d; the phantom's fields were TProductionOrder/TUnitOrder inherited members.)
2. If methods are only `UNCONDITIONAL_CALL` (never vtable DATA), check the **constructor**:
   `*(this+0)=0` (or a scalar) means offset 0 is a plain field, not a vptr → genuinely
   non-poly. Any vtable writes the ctor makes at non-zero offsets (`*(this+4)=&vtblA`) are
   **embedded members** (e.g. CMap), not the object's own vptr.
3. Confirm by decompiling a hot method: dispatch like `(**(code**)(*(int**)&this->field_0xNN
   + 0x38))(...)` on a **non-zero** field is dispatch through a held member (TSortedPtrList,
   IDirectPlay2, CMap), not self-polymorphism.

Half-finished merges leave a tell: a `.cpp` whose body was "moved to the real vtable owner"
but the phantom class/header/`symbols.csv` name were never deleted, and the address ends up
displayed under the phantom name by reccmp (symbols.csv drives the display name even when the
manual owner is a different class). Finish it: delete the phantom `.h`/`.cpp`, rename the
`symbols.csv` row to the real owner, `just regen-stubs`. Never trust "not polymorphic" without
running step 1 or 2 — reporting a disguise as a genuine data class hides a whole class merge.

### Auditing the binary for unrecovered vtables (two detection passes)
*(ex decomp-loop note 104)*


To find vtables present in the binary but not yet annotated with `// VTABLE:`:

**Pass 1 (fast, DYNCREATE only): RTTI-oracle name diff.** `config/rtti_class_oracle.csv`
lists every MFC CRuntimeClass (DECLARE_DYNCREATE) class with its ground-truth name. Diff its
class names against the classes that own a `// VTABLE:` marker
(`grep -rlE "// VTABLE:" include/game | xargs grep -hoE "^class \w+"`). Non-`C`-prefixed names
in the oracle with no marker are unrecovered game classes. This surfaced TOneTimeAnimation and
CMcWindow — both of which HAD a header/.cpp but no `// VTABLE:` marker (so they were excluded
from the "recovered" set precisely because they lacked the annotation).

**Pass 2 (thorough, catches non-DYNCREATE): direct vtable scan.** DYNCREATE-only RTTI misses
polymorphic classes without CRuntimeClass (CObject-helper families, TEvent subclasses,
dialog-template subclasses, TBitmapResourceLoader-style classes). Enumerate every `.rdata`
datum in ~0x63c000-0x672000 that (a) is referenced from `.text` by a `mov [reg], offset` and
(b) holds a run of >=2 pointers into code; subtract the `// VTABLE:` marker set; drop MFC/CRT
library vtables (CObject/CWnd/CDialog/CCmdTarget/common-controls/AFX_* module-state) and
DAT_-sentinel false positives. Caveat: vtables installed only through a shared runtime helper
(no direct `mov [reg], offset vtbl`) are a blind spot for both passes.

**Two recurring recovery shapes once found:**
- *Marker-only miss* (class fully modeled, marker absent): add `// VTABLE:` and drive the few
  mismatched slots to 100% (CMcWindow: scalar-dtor + real dtor + GetMessageMap + PreCreateWindow
  + OnCommand overrides, all ex-stubs with Ghidra placeholder names).
- *Wrong-inheritance miss* (modeled as a flat `: public CObject` with duplicated base fields):
  re-parent to the real RTTI base, add the marker, drop the duplicated fields, and model the
  handful of overridden slots (TOneTimeAnimation -> TAnimation). RTTI `base_descriptor` in the
  oracle is the ground truth for the parent.

A leaf trivial destructor whose original is a single `mov [ecx], <base-most vftable>; ret` is a
fully ICF-collapsed chain; our out-of-line base dtors emit `mov own_vtbl; jmp ~Base` instead, so
that one function stays low while the vtable and scalar dtor still reach 100% — accept it (Hard
Rule 12). The `IMPLEMENT_RUNTIMECLASS` CRuntimeClass DATA global must be named `class<Class>` in
symbols.csv (not the generic `classRuntimeClass` placeholder) or GetRuntimeClass stalls at 50%.

### Ghidra's provisional class namespace can mis-home a method to a sibling class
*(ex decomp-loop note 108)*


Ghidra auto-names methods with a provisional namespace that can be a DIFFERENT class from the
recovered one — e.g. `TacticalBattleView::` (no `T` prefix) is NOT the recovered
`TTacticalBattleView`; here three "TacticalBattleView" methods were actually `TTacticalBattle`
methods. Before homing a stubbed method onto the class its symbols.csv name suggests, VERIFY
`this`'s real type by cross-checking every `this+off` access against candidate class headers
(field offsets, the vtable, the method-address cluster range). Seven field matches
(battleView8/currentSideC/field10/tacticalPlayer14/18/selectedUnit1c) pinned `this` as
`TTacticalBattle`, not the view. Fix the symbols.csv namespace and put the body in the right
`.cpp`. (Hard Rule 6: names are provisional; pair by behavior, not by name.)
