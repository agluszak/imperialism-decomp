#include "game/ui_screens/TTerrainHelpWindow.h"

#include "game/ui_core/THelpMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TTerrainHelpWindow, TFloatWindow)

// FUNCTION: IMPERIALISM 0x00504d40
TTerrainHelpWindow::TTerrainHelpWindow() : TFloatWindow() {}

// FUNCTION: IMPERIALISM 0x00504da0
TTerrainHelpWindow::~TTerrainHelpWindow() {}

// slot 0x28 — TFloatWindow::Close override: base close/reset, then drop the
// help manager's pending terrain-help dialog-view pointer.
// FUNCTION: IMPERIALISM 0x00504dc0
void TTerrainHelpWindow::Close() {
  TFloatWindow::Close();
  g_pHelpMgr->pendingDialogViewC = 0;
}
