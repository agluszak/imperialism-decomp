#include "game/ui_invalidation_guard.h"

#include "game/mfc.h"
#include "game/global_data_tables.h"

// Variadic so assert-style call sites (which push a source path + line) call this
// directly and clean the stack, matching the original — the body ignores all args.
// FUNCTION: IMPERIALISM 0x0049d620
undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(...) {
  undefined4 previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  SetGlobalUiInvalidationFlagAndReturnPrevious(previous);
  return 0;
}

// Nil-pointer assert helper for USmallViews
void FailNilPointerInUSmallViews(int line) {
  const char kUSmallViewsCppPath[] = "D:\\Ambit\\Cross\\USmallViews.cpp";
  GAME_FAIL_NIL_POINTER();
  TemporarilyClearAndRestoreUiInvalidationFlag(kUSmallViewsCppPath, line);
}
