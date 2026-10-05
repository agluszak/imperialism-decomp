#include "game/gfx/TDlgWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/gfx/ui_invalidation_guard.h"

IMPLEMENT_DYNCREATE(TDlgWindow, TWindow)

// FUNCTION: IMPERIALISM 0x00500320
TDlgWindow::TDlgWindow() : TWindow() {}

// FUNCTION: IMPERIALISM 0x00500380
TDlgWindow::~TDlgWindow() {}

// FUNCTION: IMPERIALISM 0x005003a0
void TDlgWindow::Activate(unsigned char active) {
  TWindow::Activate(active);
  TemporarilyClearAndRestoreUiInvalidationFlag(g_szUGameWindowSourcePath_00696bc0, 0x27a);
  if (g_pDisplayMgr->dialogActiveFlag != 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szUGameWindowSourcePath_00696bc0, 0x27f);
  }
}
