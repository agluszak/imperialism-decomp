#include "game/ui_screens/THelpWindow.h"

#include "game/ui_core/THelpMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(THelpWindow, TFloatWindow)

// FUNCTION: IMPERIALISM 0x00504bf0
THelpWindow::THelpWindow() : TFloatWindow() {}

// FUNCTION: IMPERIALISM 0x00504c50
THelpWindow::~THelpWindow() {}

// FUNCTION: IMPERIALISM 0x00504c70
void THelpWindow::Close() {
  TFloatWindow::Close();
  g_pHelpMgr->pendingDialogView8 = 0;
}
