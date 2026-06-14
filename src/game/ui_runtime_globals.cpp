#include "game/ui_runtime_globals.h"

#include "game/mcappui_globals.h"

// FUNCTION: IMPERIALISM 0x00489a50
undefined4 SetGlobalUiInvalidationFlagAndReturnPrevious(undefined4 newValue) {
  undefined4 previous = g_McAppUiActiveFlag_006950AC;
  g_McAppUiActiveFlag_006950AC = newValue;
  return previous;
}
