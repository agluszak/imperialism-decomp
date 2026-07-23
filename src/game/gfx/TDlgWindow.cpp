#include "game/gfx/TDlgWindow.h"
#include "game/globals/prelude.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// Application/document-root pointer @ 0x6a2158; its +0x0a field gates the line-0x27f assert.
static const unsigned int kAddrMainViewHostPtr = 0x006a2158;

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
TDlgWindow::~TDlgWindow() {}

// Run the base TWindow assert hook, then fire the UGameWindow line-634 invalidation assert;
// fire the line-639 assert too when the main view host's +0x0a field is set.
// FUNCTION: IMPERIALISM 0x005003a0
void TDlgWindow::AssertMcAppUILine2358(int) {
  TWindow::AssertMcAppUILine2358(0);
  AssertUGameWindowInvalidation(g_szUGameWindowSourcePath_00696bc0, 0x27a);
  void* mainViewHost = *reinterpret_cast<void**>(kAddrMainViewHostPtr);
  if (*reinterpret_cast<short*>(reinterpret_cast<char*>(mainViewHost) + 0xa) != 0) {
    AssertUGameWindowInvalidation(g_szUGameWindowSourcePath_00696bc0, 0x27f);
  }
}
