#pragma once

#include "decomp_types.h"
#include "game/GameAssert.h"

// 0x0049d620 — __cdecl flag toggler that ignores every argument (`ret`, no arg
// reads). Assert-style call sites push a source path + line before calling it and
// clean the stack themselves; modelling it variadic lets both f() and
// f(path, line) call 0x49d620 directly instead of routing arg-passing calls through
// a separate forwarder (which broke pairing at those call sites).
int TemporarilyClearAndRestoreUiInvalidationFlag(...);
int __stdcall PumpUiMessagesAndBackgroundTasks(int nTaskPumpMode);

// Nil-pointer assert helper for USmallViews
void FailNilPointerInUSmallViews(int line);

// Inline helper for nil-pointer asserts with source path
static __inline void FailNilPointerWithAssert(const char* sourcePath, int line) {
  GAME_FAIL_NIL_POINTER();
  TemporarilyClearAndRestoreUiInvalidationFlag(sourcePath, line);
}
