#include "game/ui_invalidation_guard.h"

#include "game/ui_runtime_globals.h"

// FUNCTION: IMPERIALISM 0x0049d620
undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(void) {
  undefined4 previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  SetGlobalUiInvalidationFlagAndReturnPrevious(previous);
  return 0;
}
