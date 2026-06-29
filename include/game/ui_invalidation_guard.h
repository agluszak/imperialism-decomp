#pragma once

#include "decomp_types.h"
#include "game/GameAssert.h"

undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(void);
void TemporarilyClearAndRestoreUiInvalidationFlag(const char* sourceFile, int line);
int __stdcall PumpUiMessagesAndBackgroundTasks(int nTaskPumpMode);

// Nil-pointer assert helper for USmallViews
void FailNilPointerInUSmallViews(int line);

// Inline helper for nil-pointer asserts with source path
static __inline void FailNilPointerWithAssert(const char* sourcePath, int line) {
  GAME_FAIL_NIL_POINTER();
  TemporarilyClearAndRestoreUiInvalidationFlag(sourcePath, line);
}
