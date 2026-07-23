#include "game/THelpWindow.h"

#include "game/THelpMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x00504b50
// THelpWindow::CreateObject

// SYNTHETIC: IMPERIALISM 0x00504bd0
// THelpWindow::GetRuntimeClass

IMPLEMENT_DYNCREATE(THelpWindow, TFloatWindow)

// FUNCTION: IMPERIALISM 0x00504bf0
THelpWindow::THelpWindow() : TFloatWindow() {}

// SYNTHETIC: IMPERIALISM 0x00504c20
// THelpWindow::`scalar deleting destructor'
THelpWindow::~THelpWindow() {}

// slot 0x28 — TFloatWindow::Close override: base close/reset, then drop the
// help manager's pending general-help dialog-view pointer.
// FUNCTION: IMPERIALISM 0x00504c70
void THelpWindow::Close() {
  TFloatWindow::Close();
  g_pHelpMgr->pendingDialogView8 = 0;
}
