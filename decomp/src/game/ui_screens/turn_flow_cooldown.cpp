#include "game/ui_screens/turn_flow_cooldown.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"

// FUNCTION: IMPERIALISM 0x0057b900
bool IsTurnFlowCooldownActiveAndResetExpiredState(void) {
  if (g_nTurnCooldownDeferCounter < 1) {
    g_nTurnCooldownDeferCounter = 0;
    g_nTurnCooldownSideFlag = 1;
    return false;
  }
  return true;
}
