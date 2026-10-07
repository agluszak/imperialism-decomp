#include "game/ui_core/TFloatWindow.h"
#include "game/ui_tags_widgets.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/globals/ui_core_globals.h"

IMPLEMENT_DYNCREATE(TFloatWindow, TWindow)

// FUNCTION: IMPERIALISM 0x00491fb0
TFloatWindow::TFloatWindow() : TWindow() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// FUNCTION: IMPERIALISM 0x00492140
TFloatWindow::~TFloatWindow() {}

// FUNCTION: IMPERIALISM 0x004922d0
void __stdcall AssertMcAppUiDialogStateAndMarkWindow(int arg1, TWindow* window, int arg3, int arg4,
                                                     int arg5) {
  ReportAssertionFailure(g_szMcAppUiSourcePath, 0x8c9);
  window->windowFlags = 0x80;
}

// FUNCTION: IMPERIALISM 0x00492310
int TFloatWindow::GetWindowTypeTag() {
  return kControlTagFwnd;
}

// FUNCTION: IMPERIALISM 0x00492330
void TFloatWindow::Close() {
  busyFlag = 0;
  if (nativeWindow != 0 && nativeWindow->m_hWnd != 0) {
    SendMessageA(nativeWindow->m_hWnd, 0x468, 1, controlTag);
  }
  if (childList != 0) {
    POSITION pos = childList->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList->GetNext(pos));
      child->Close();
    }
  }
  Show(0, true);
}
