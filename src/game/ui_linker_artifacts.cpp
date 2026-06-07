// Quarantined UI linker artifacts.
//
// These are 5-byte incremental-link `jmp <ctor>` thunks (ILT stubs) emitted by
// the original toolchain. They have no clean C++ source equivalent in this
// non-incremental rebuild and are NOT expected to match (heuristic 93) — do not
// chase their score. They are isolated here, deliberately OUT of the class
// public API (TView.h / TControl.h), so that the real class headers advertise
// only real members. Placement-new is used purely as the bridge that reproduces
// the `jmp` target's construction; this file is the sanctioned quarantine for
// that idiom (CLAUDE.md hard rules 7 and 15). The durable fix is converting the
// remaining derived UI classes to real inheritance, which retires these thunks
// entirely.

#include "game/TControl.h"
#include "game/TView.h"

#include <new>

// __fastcall keeps `self` in ecx, matching the thiscall ABI of the original
// `jmp <ctor>` target (the callee expects `this` in ecx). This is the sanctioned
// quarantined-thunk use of __fastcall, not a calling-convention cast bridge.

// KNOWN LINKER ARTIFACT: 0x004064e2 is `jmp TView::TView`.
// FUNCTION: IMPERIALISM 0x004064e2
void __fastcall ConstructTViewBaseStateThunk(TView* self) {
  new (self) TView();
}

// KNOWN LINKER ARTIFACT: 0x004087fb is `jmp TControl::TControl`.
// FUNCTION: IMPERIALISM 0x004087fb
void __fastcall ConstructTControlBaseStateThunk(TControl* self) {
  new (self) TControl();
}
