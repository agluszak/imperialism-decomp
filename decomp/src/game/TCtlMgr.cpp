#include "game/TCtlMgr.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

IMPLEMENT_DYNCREATE(TCtlMgr, TControl)

// FUNCTION: IMPERIALISM 0x00492db0
void TCtlMgr::AssertMcAppUiInvalidationFlagSet(int arg1, int arg2) {
  if (g_McAppUiFlag_006A1B5C == 0) {
    ReportAssertionFailure(g_szMcAppUiHeaderPath, 0x5a7);
  }
}

// FUNCTION: IMPERIALISM 0x00492ea0
TCtlMgr::~TCtlMgr() {}
