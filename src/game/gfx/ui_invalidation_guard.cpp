#include "game/ui_invalidation_guard.h"

#include "game/mfc.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// Variadic so assert-style call sites (which push a source path + line) call this
// directly and clean the stack, matching the original — the body ignores all args.
// FUNCTION: IMPERIALISM 0x0049d620
int TemporarilyClearAndRestoreUiInvalidationFlag(...) {
  int previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  SetGlobalUiInvalidationFlagAndReturnPrevious(previous);
  return 0;
}

// Nil-pointer assert helper for USmallViews
void FailNilPointerInUSmallViews(int line) {
  const char kUSmallViewsCppPath[] = "D:\\Ambit\\Cross\\USmallViews.cpp";
  GAME_FAIL_NIL_POINTER();
  TemporarilyClearAndRestoreUiInvalidationFlag(kUSmallViewsCppPath, line);
}
