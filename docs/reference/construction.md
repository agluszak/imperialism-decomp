# Real C++ construction and inheritance — full detail

The crisp principles live in `AGENTS.md` ("Hard rules: real C++ construction and
inheritance"). This file holds the long-form rules, examples, and rationale. The
mechanically-checkable parts are enforced by `just antipattern-gate` (manual vptr
writes, `new (this)`, `operator new`/`__cdecl` factories, `__thiscall`
reinterpret_cast) and `just marker-gate`.

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

### 2. No manual vtable writes (enforced by `just antipattern-gate`)

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

### 7. Placement-new is not a substitute for base construction (enforced by `just antipattern-gate`)

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

### 8. Retire bridge helpers as classes become understood (count baseline-tracked by `just antipattern-gate`)

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

#### Destructor declaration and definition placement is binary evidence, not style

Do not move a destructor between a header and a `.cpp` merely to silence Clang, make a
vtable emit, or improve one local comparison. Visibility changes VC5 inlining and COMDAT
folding across every constructor, deleting destructor, derived destructor, and vtable that
uses the class.

Use this policy:

* If the original has no ordinary destructor body and real members/bases already express
  teardown, leave the destructor implicit. Do not add an empty body to claim a scalar
  deleting destructor.
* If the original has a standalone ordinary destructor address, declare it in the header
  and define it in the owning `.cpp` with the `// FUNCTION:` marker.
* Put the body inline in the header only when listings at real call sites prove the retail
  compiler expanded that destructor there. Check multiple call sites before changing a
  shared base.
* A polymorphic class with a listing-proven vtable that has no destructor slot may have a
  non-virtual destructor. Delete it only through the exact concrete type; deleting through
  a base pointer is a source-model bug.
* Scalar deleting destructors remain compiler-generated and `// SYNTHETIC:` regardless of
  where the ordinary destructor lives.

After any destructor visibility change, compare the ordinary destructor when it has an
address and run `just vtable` for the class and its affected derived siblings. A local
destructor score gain does not justify collateral COMDAT folding or vtable regressions.

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

### 17. No `operator new`/`operator delete` factories or `__cdecl` factory helpers (baseline-tracked by `just antipattern-gate`)

Class-declared `operator new`/`operator delete` and `__cdecl` free-function factory /
class-name helpers (e.g. `CreateTViewInstance`, `GetTViewClassNamePointer`) are a
**banned porting approach**. They are decompiler/codegen artifacts, not faithful source
reconstruction.

Do not add them — not even when an existing factory elsewhere already uses the inline
`operator new` + `new T()` shape (that older "EH-new factory" pattern is retired; do not
use it as a template for new work).

Instead, port the real thing: resolve the class's vtable-slot ILT thunks
(`0x40xxxx JMP`) to their real bodies, give the dummy `vmethod_*` stubs real bodies with
`// FUNCTION:` markers, and let real C++ inheritance own construction and the vtable.
"Port more methods to class X" means real virtual methods on the real class — not a
factory and not `operator new`.

The existing `operator new`/`operator delete` sites are baseline-tracked so they ratchet
down; new occurrences fail the gate.
