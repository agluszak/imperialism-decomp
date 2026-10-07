#include "game/gfx/ui_invalidation_guard.h"

#include "game/mfc.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

// FUNCTION: IMPERIALISM 0x0049d620
int ReportAssertionFailure(...) {
  int previous = SetInvalidationFlag(0);
  SetInvalidationFlag(previous);
  return 0;
}
