#include "game/ui_core/TFloatWindow.h"
#include "game/ui_tags_widgets.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/globals/ui_core_globals.h"

// SYNTHETIC: IMPERIALISM 0x00491e00
// TFloatWindow::CreateObject
// SYNTHETIC: IMPERIALISM 0x00491f90
// TFloatWindow::GetRuntimeClass

IMPLEMENT_DYNCREATE(TFloatWindow, TWindow)

// FUNCTION: IMPERIALISM 0x00491fb0
TFloatWindow::TFloatWindow() : TWindow() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00492110
// TFloatWindow::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00492140
TFloatWindow::~TFloatWindow() {}

// Dead helper: unconditional McAppUI.cpp:0x8c9 assert, then stamps the window's +0x9c
// flag word 0x80 on its second argument (loaded while the assert's pushed args are
// still on the stack). Five-argument __stdcall; no callers survive.
// FUNCTION: IMPERIALISM 0x004922d0
void __stdcall AssertMcAppUiDialogStateAndMarkWindow(int arg1, TWindow* window, int arg3,
                                                    int arg4, int arg5) {
  TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0x8c9);
  window->windowFlags = 0x80;
}

// FUNCTION: IMPERIALISM 0x00492310
int TFloatWindow::GetWindowTypeTag() {
  return kControlTagFwnd;
}

// FUNCTION: IMPERIALISM 0x00492330
void TFloatWindow::Close() {
  busyFlag98 = 0;
  if (nativeWindow50 != 0 && nativeWindow50->m_hWnd != 0) {
    SendMessageA(nativeWindow50->m_hWnd, 0x468, 1, controlTag);
  }
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->Close();
    }
  }
  Show(0, 1);
}
