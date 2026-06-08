# Imperialism Decomp — Agent Guide

Decompilation workspace for the Windows game **Imperialism (1997)**. We reverse the
binary into matching C++, rebuild it with the original MSVC500 toolchain in
Docker/Wine, and track per-function similarity with `reccmp`. The goal is a
byte-faithful, reproducible-in-git rebuild.

This file is the contract: the invariants below hold for all work. Per-workflow
detail lives in **skills** (`.claude/skills/`); read the relevant skill before
starting that kind of task.

## Skills (how to do each workflow)

- **`decomp-loop`** — the core function-porting loop (promote → shape pass → data
  pass → build → compare). Its `heuristics.md` is the 85-entry matching playbook.
- **`ghidra`** — inspect `Imperialism.exe` via pyghidra (listing, decompile, vtable
  dump, cdecl/thiscall scan) and the interactive function-documentation methodology.
- **`quality-control`** — build, reccmp detect/compare/stats, canaries, gates,
  formatting, and reccmp pairing-failure diagnosis.
- **`class-recovery`** — class/vtable reconstruction, Mac evidence, the vcall facade
  registry, and facade→virtual migration.

## Docs (the durable record)

- `docs/worklog.md` — chronological execution log (timestamps, commands, score
  deltas). The ground truth for what happened.
- `docs/toolchain.md` — compiler/linker forensics and reproduction decisions.
- `docs/reference/` — layout/contract and game-domain references (struct layouts,
  function/entry-chain map, bitmap IDs, tech unlocks).

## Hard Rules

1. No inline assembly.
2. Use `just` targets for normal workflow (`tooling-check`, `build`, `detect`,
   `compare`, `stats`, `promote`, `sync-ownership`, `regen-stubs`). Do not run raw
   `docker` or `uv run reccmp-*` when a `just` target exists; if no target exists,
   keep the direct command minimal and add a target afterward.
3. `// FUNCTION: IMPERIALISM 0x...` must be immediately followed by the function
   declaration — no comment or blank line between them.
4. One owned implementation per address in manual source; no duplicate `// FUNCTION`
   for the same address across manual files and stubs.
5. After editing markers/ownership, run `just sync-ownership` → `just regen-stubs` →
   `just build`.
6. Keep naming from Ghidra unless there is a concrete semantic reason to rename; never
   rename for style only.
7. Keep class-owned functions in `src/game/<ClassName>.cpp`; non-class/global trade
   code in `src/game/trade_screen.cpp`. Do not hand-edit generated files under
   `src/ghidra_autogen/`, `src/autogen/stubs/`, or `include/ghidra_autogen/`.
8. Promote repeated `this + offset` / `reinterpret_cast` access that maps to a stable
   class region into a typed class field (or typed view struct) instead of cast-helper
   indirection.
9. Keep external thunk declarations in the generic repo form (`undefined4 ...(void)`)
   and use typed local function-pointer casts at callsites; changing thunk
   declaration signatures directly causes MSVC name-mangling linker breaks.
10. MSVC500 keeps `for` loop variables in function scope; do not redeclare the same
    loop variable name later in the same function.
11. For vtable calls in manual code, call through generated facades in
    `include/game/generated/vcall_facades.h` (or real virtuals) — no local
    `typedef ...Fn` + `reinterpret_cast` blocks, no raw `vftable[...]` indexing. Keep
    low-level slot-cast mechanics isolated in `include/game/vcall_runtime.h`.
12. `config/vtable_slots.csv` is the single source of truth for generated vcall
    wrappers; after changing it, run `just gen-vcall-facades` before build/compare.
13. The raw-vtable gate (`just vtable-gate`) must pass; do not add new raw-vtable
    patterns in files not already baseline-tracked.
14. `just session-loop` mutates `reccmp-project.yml` ignore lists; run it only when you
    explicitly intend to rewrite ignore configuration.
15. Mac CodeWarrior evidence (vendored at `vendor/macos_codewarrior/`) is a
    name/signature **oracle only** — it must never assign Windows addresses, calling
    conventions, vtables, or inheritance.

## Hard rules: real C++ construction and inheritance

These rules are mandatory. Do not use bridge thunks, placement-new shims, manual vtable writes, or fake runtime helpers when a real C++ construct can express the same thing.

### 1. Prefer real inheritance over construction bridges

If a class is structurally a derived class, model it as real C++ inheritance:

```cpp
class TDerived : public TBase {
public:
  TDerived();
};
```

Do not model base construction with helper calls like:

```cpp
ConstructTBaseAtThis(this);
new (this) TBase();
VCall_RuntimeBaseCtor(this);
```

Those are temporary decompiler artifacts, not proper source reconstruction.

A derived constructor must call the base constructor naturally:

```cpp
TDerived::TDerived()
    : TBase(),
      field10(0),
      memberString(),
      field20(1) {
}
```

not by explicitly constructing the base subobject inside the body.

### 2. No manual vtable writes

Never write vtable pointers by hand in source:

```cpp
*(void**)this = &SomeVtable;
```

or:

```cpp
vptr = g_vtblSomething;
```

The class `// VTABLE:` annotation and C++ inheritance must own vtable emission. If matching requires a vptr write, the class model is probably wrong: missing inheritance, wrong base class, wrong constructor/destructor shape, or fake bridge code.

Manual vtable writes are only allowed in explicitly quarantined low-level runtime files, and only with a comment proving that the original code is not normal C++ object construction.

### 3. Constructor bodies are not for default initialization when member-initializers match better

For constructors, prefer member-initializer lists whenever the original initializes fields before constructing later non-POD members.

Correct:

```cpp
TView::TView()
    : TEventHandler(),
      field10(0x7fffffff),
      field14(0),
      flag4c(1),
      sharedStringRef(),
      field5c(0) {
}
```

Suspicious:

```cpp
TView::TView() {
  field10 = 0x7fffffff;
  field14 = 0;
  flag4c = 1;
  field5c = 0;
}
```

Reason: if the class has real members such as `CString`, `CArray`, `CPtrArray`, or other non-trivial objects, body assignments force those members to be constructed before the body. The original MSVC output often proves the intended source shape by ordering scalar initializers before member constructors.

### 4. Declaration order is part of the reconstruction

C++ initializes members in declaration order, not initializer-list order. Therefore field declaration order must match the original layout and constructor emission.

Do not reorder fields just to make source look nicer. If constructor matching depends on a member being constructed after scalar fields, the member must be declared after those scalar fields.

If a field is currently padding but the constructor writes to it, promote it to a real named field only when there is evidence.

### 5. Use real member objects, not raw storage plus init helpers

If a field behaves like a `CString`, `CArray`, `CPtrArray`, `CRect`, or other real object member, declare it as that type.

Prefer:

```cpp
CString name;
```

over:

```cpp
unsigned char nameStorage[4];

InitializeCString(&nameStorage);
```

Raw storage is allowed only when the actual type is unknown. Once constructor/destructor evidence identifies the type, replace raw storage with the real member type.

### 6. Do not create fake source just to match linker artifacts

Incremental-link thunks, import thunks, ILT jump stubs, and other linker artifacts are not semantic source code.

Do not write fake C++ to reproduce:

```asm
jmp SomeConstructor
```

Do not use placement-new, function-pointer casts, or artificial wrapper calls solely to match ILT thunks.

Instead, mark the thunk as a known linker artifact and focus on reconstructing the real target function and the real class hierarchy.

### 7. Placement-new is not a substitute for base construction

Placement-new is forbidden for constructing a base class at `this` when real inheritance can express the relationship.

Forbidden:

```cpp
new (this) TControl();
```

Correct:

```cpp
class TButton : public TControl {
public:
  TButton() : TControl() {}
};
```

Placement-new is only acceptable for actual placement-new semantics: object pools, custom allocators, explicit reconstruction into storage, or code where the original program really constructs a separate object into a buffer.

### 8. Retire bridge helpers as classes become understood

Any helper named like:

```cpp
ConstructXBaseState
ConstructXAtThis
VCall_X_Runtime
thunk_ConstructX
```

is presumed temporary unless proven otherwise.

When class layout, vtable, constructor, and base relationship are known, replace the helper with real C++ inheritance, member constructors, and virtual methods.

Do not build new architecture on top of these helpers.

### 9. Virtual calls should be real virtual calls

If the original dispatches through a vtable slot and the target belongs to a known class hierarchy, model it as a virtual method.

Prefer:

```cpp
object->ApplyPolicyForNation(nation);
```

over:

```cpp
VCall_GreatPower_ApplyPolicyForNationSlotA1(object, nation);
```

Slot-named vcall helpers are temporary scaffolding. Keep them only when the receiver type or hierarchy is still unknown.

Once the class and slot are understood, rename the method and move it onto the class.

### 10. Matching is not allowed to corrupt the source model

Do not add source-level hacks merely to improve a local reccmp score if they make the class model less true.

Bad local fixes include:

```cpp
manual vptr writes
fake placement-new bridges
function-pointer casts to constructors
artificial volatile references
dummy calls only to force emission
raw byte storage for known object members
duplicated base fields inside derived classes
```

A 70% match with correct architecture is better than a 100% match produced by fake source that blocks later hierarchy recovery.

### 11. Out-of-line constructor emission should come from real users

If a constructor disappears because the compiler inlined or folded it away, do not force it with dummy references.

The proper fix is to convert real derived classes to real inheritance so their constructors naturally reference the base constructor.

Example:

```cpp
class TStaticText : public TControl {
public:
  TStaticText();
};
```

This is better than adding a fake standalone function whose only purpose is to keep `TControl::TControl` emitted.

### 12. Evidence required for inheritance

Use real inheritance when at least one of these is true:

* constructor behavior shows base constructor followed by derived initialization;
* destructor behavior shows base destructor sequencing;
* vtable layout matches a base/derived relationship;
* field layout begins with a known base object;
* Mac symbols or debug names identify the class relationship;
* multiple derived classes share the same prefix layout and virtual slot structure.

If evidence is weak, leave a temporary helper, but mark it as temporary and do not expand it.

### 13. Constructor reconstruction checklist

Before accepting a constructor, check:

* Are all base classes modeled as real bases?
* Are all known object members declared as real member types?
* Are scalar initializations in the initializer list when original ordering requires it?
* Does declaration order explain constructor order?
* Are there any manual vtable writes? If yes, fix the class model.
* Are there placement-new calls on `this`? If yes, replace with inheritance unless proven intentional.
* Are ILT/linker thunks being mistaken for source-level functions?
* Did the compiler emit the derived vptr naturally at the correct point?
* Does EH state ordering match non-trivial member construction/destruction?

### 14. Destructors follow the same rules

Destructors must also be real C++ destructors.

Do not manually call fake base destructors or write base vtables unless the original is genuinely non-standard runtime code.

Prefer:

```cpp
TDerived::~TDerived() {
  // derived cleanup only
}
```

and let C++ emit member and base destruction.

If the original destructor writes base vtables during teardown, that should normally come from real inheritance, not manual stores.

### 15. Temporary scaffolding must be named and isolated

If a helper is unavoidable because the hierarchy is not understood yet, name it as temporary and include a removal condition.

Example:

```cpp
// TEMP: bridge until TTradePanel is converted to real TControl inheritance.
// Remove once derived constructor calls TControl::TControl naturally.
void ConstructTTradePanelControlPrefix(TTradePanel* self);
```

Do not give temporary scaffolding clean final names that make it look architectural.

### 16. Scalar deleting destructors must be compiler-generated (SYNTHETIC), never hand-written

A scalar deleting destructor (`??_G<Class>` / `??_E<Class>`) is code the compiler emits
into the vtable. It must NEVER be hand-written as source.

Forbidden — a hand-written destruct-and-maybe-free bridge:

```cpp
// FUNCTION: IMPERIALISM 0x00586d10
void* TAmtBarCluster::DestructAndMaybeFree(int freeSelfFlag) {
  thunk_DestructBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(this);
  }
  return this;
}
```

```cpp
// also forbidden: the __fastcall bridge shape
X* __fastcall DestructXAndMaybeFree(X* self, int unusedEdx, unsigned char freeSelfFlag);
```

Required — model the class with real inheritance from a polymorphic base, make the
ordinary destructor IMPLICIT, and claim the scalar-deleting address with a `SYNTHETIC`
marker plus an exact backtick name in `config/symbols.csv` so reccmp pairs it:

1. `config/symbols.csv`: set the scalar-deleting address's name to
   `` Class::`scalar deleting destructor' `` (backtick + trailing apostrophe). This is the
   ONLY way it pairs — a compiler-generated body has no source line for marker matching.
2. Source: delete the hand-written body/bridge; replace with
   `// SYNTHETIC: IMPERIALISM 0x<addr>` then `` // Class::`scalar deleting destructor' ``.
3. Header: remove any `virtual ~Class();` declaration AND any `~Class() {}` body; rely on
   the base's virtual destructor. A hand-written empty `~Class(){}` COMDAT-folds with
   sibling empty dtors and triggers reccmp "Debug data out of sync", collaterally dropping
   the adjacent ctor.
4. `just sync-ownership` → `just regen-stubs` → `just build` → `just compare`.

Canonical example: `src/game/TSortedByRelationshipList.cpp` (+ its header). This only
works once the class is genuinely polymorphic (its base has a virtual destructor); if it
is not, recover the real inheritance first rather than hand-writing the destructor.
Watch for false positives: a `Destruct*AndMaybeFree` NAME is not proof — read the body
before converting.


## MSVC500 calling-convention guardrail

- **Ghidra's calling-convention attribution is frequently WRONG** (it default-labels
  unknown functions `__cdecl`; ~33% of "defined `__cdecl`" are really `__thiscall`, and
  it mislabels `__fastcall`/`__thiscall`/vtable dispatch). Treat every convention from
  Ghidra/decompiler output as a hypothesis to verify against the assembly (who sets
  `ecx`/`edx`, who cleans the stack), never as ground truth.
- **Model real classes with real methods/virtuals — do not fake calling conventions
  with `reinterpret_cast` to paper over Ghidra's labels.** This is the single most
  repeated correction.
  - If a call is `thiscall`, the callee is a class method: declare it as a real method
    on the real class and call `obj->Method(args)`. Do NOT cast a free-function pointer
    to a fake `__fastcall(void*, int /*edx*/, ...)` shape with a dummy `edx`.
  - If a call is a **vtable dispatch**, model the real C++ class with real `virtual`
    methods (in the correct slot order — verify the slot offset in the disassembly) and
    call `obj->Virtual(args)`. Do NOT route it through the `vcall_runtime` /
    `VCall_*` facades; those inject a spurious `xor edx,edx` and reload the vtable per
    call. Owning the real virtual lets MSVC cache the vtable in a register across calls,
    matching the original. (The `vcall_runtime` facade layer is legacy scaffolding we
    intend to delete entirely — do not add to it; migrate off it.)
- A `reinterpret_cast` that only adjusts a return type or argument types of a genuinely
  same-convention free function (e.g. a real `__cdecl(void)` thunk) is fine. Faking the
  *convention* (esp. thiscall-as-fastcall-with-dummy-edx) is not.
- For an unavoidable free-function bridge where no class can yet be modeled, prefer
  `__fastcall` and keep the bridge out of primary method bodies — but first ask whether
  the right fix is to recover the owning class.

## Logging policy

- Keep execution detail in `docs/worklog.md` (one timestamped entry per session/change
  with commands and score deltas).
- Don't duplicate the same long status across multiple files.
- Persist transferable matching lessons as numbered notes in
  `.claude/skills/decomp-loop/heuristics.md`.

