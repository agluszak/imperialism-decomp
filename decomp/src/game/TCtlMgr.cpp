#include "game/TCtlMgr.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x0048eaf0
// TCtlMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCtlMgr, TControl)
// The destructor below is a real 104-byte compiler-emitted body (member/EH
// teardown); the NOOP annotation above applies only to the default ctor.

// SYNTHETIC: IMPERIALISM 0x00492de0
// TCtlMgr::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00492db0
void TCtlMgr::AssertMcAppUiInvalidationFlagSet(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
  if (g_McAppUiFlag_006A1B5C == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiHeaderPath_006943CC, 0x5a7);
  }
}

// FUNCTION: IMPERIALISM 0x00492ea0
TCtlMgr::~TCtlMgr() {}

// SYNTHETIC: IMPERIALISM 0x0048ea00
// TCtlMgr::CreateObject
