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

// FUNCTION: IMPERIALISM 0x00504dc0
void TTerrainHelpWindow::Close() {
  TFloatWindow::Close();
  g_pHelpMgr->pendingDialogViewC = 0;
}
