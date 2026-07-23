#include "game/ui_screens/turn_flow_cooldown.h"

#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"

// FUNCTION: IMPERIALISM 0x0057b900
bool IsTurnFlowCooldownActiveAndResetExpiredState(void) {
  if (g_nTurnCooldownDeferCounter006A43C4 < 1) {
    g_nTurnCooldownDeferCounter006A43C4 = 0;
    g_nTurnCooldownSideFlag00698B10 = 1;
    return false;
  }
  return true;
}
