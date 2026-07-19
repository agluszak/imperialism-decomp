#include "game/TTerrainHelpWindow.h"

#include "game/THelpMgr.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x00504ca0
// TTerrainHelpWindow::CreateObject

// SYNTHETIC: IMPERIALISM 0x00504d20
// TTerrainHelpWindow::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTerrainHelpWindow, TFloatWindow)

// FUNCTION: IMPERIALISM 0x00504d40
TTerrainHelpWindow::TTerrainHelpWindow() : TFloatWindow() {}

// SYNTHETIC: IMPERIALISM 0x00504d70
// TTerrainHelpWindow::`scalar deleting destructor'
TTerrainHelpWindow::~TTerrainHelpWindow() {}

// slot 0x28 — TFloatWindow::CallVoidSlotA0 override: base close/reset, then drop the
// help manager's pending terrain-help dialog-view pointer.
// FUNCTION: IMPERIALISM 0x00504dc0
void TTerrainHelpWindow::CallVoidSlotA0() {
  TFloatWindow::CallVoidSlotA0();
  g_pHelpMgr->pendingDialogViewC = 0;
}
