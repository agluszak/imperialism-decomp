#include "game/gfx/TDlgWindow.h"
#include "game/globals/prelude.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/gfx/ui_invalidation_guard.h"

// The original reaches the shared UI invalidation-flag helper through the incremental-link
// thunk; this only retypes the args of a genuine __cdecl(void) thunk (Hard Rule 9).
static __inline void AssertUGameWindowInvalidation(const char* path, int line) {
  TemporarilyClearAndRestoreUiInvalidationFlag();
}
// SYNTHETIC: IMPERIALISM 0x00500280
// TDlgWindow::CreateObject

// SYNTHETIC: IMPERIALISM 0x00500300
// TDlgWindow::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDlgWindow, TWindow)

// FUNCTION: IMPERIALISM 0x00500320
TDlgWindow::TDlgWindow() : TWindow() {}

// SYNTHETIC: IMPERIALISM 0x00500350
// TDlgWindow::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00500380
TDlgWindow::~TDlgWindow() {}

// Run the base TWindow assert hook, then fire the UGameWindow line-634 invalidation assert;
// fire the line-639 assert too while the display manager has an active dialog.
// FUNCTION: IMPERIALISM 0x005003a0
void TDlgWindow::Activate(unsigned char active) {
  TWindow::Activate(active);
  AssertUGameWindowInvalidation(g_szUGameWindowSourcePath_00696bc0, 0x27a);
  // 0x006a2158 is g_pDisplayMgr (see its // GLOBAL marker) and +0xa is its
  // dialogActiveFlag, so this is a plain typed read rather than a raw address poke.
  if (g_pDisplayMgr->dialogActiveFlag != 0) {
    AssertUGameWindowInvalidation(g_szUGameWindowSourcePath_00696bc0, 0x27f);
  }
}
