#include "game/TFloatWindow.h"
#include "game/ui_tags_widgets.h"

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
TFloatWindow::~TFloatWindow() {}

// FUNCTION: IMPERIALISM 0x00492310
int TFloatWindow::GetWindowTypeTag() {
  return kControlTagFwnd;
}

// FUNCTION: IMPERIALISM 0x00492330
void TFloatWindow::Close() {
  busyFlag98 = 0;
  if (nativeWindow50 != 0 && nativeWindow50->m_hWnd != 0) {
    SendMessageA(reinterpret_cast<HWND>(nativeWindow50->m_hWnd), 0x468, 1, controlTag);
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
