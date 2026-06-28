#include "game/TFloatWindow.h"

extern "C" CRuntimeClass PTR_s_TFloatWindow_006496d8;

// FUNCTION: IMPERIALISM 0x00491e00
TView* TFloatWindow::CreateTFloatWindowInstance() {
  return new TFloatWindow();
}
IMPLEMENT_DYNCREATE(TFloatWindow, TWindow)

// FUNCTION: IMPERIALISM 0x00491fb0
TFloatWindow::TFloatWindow() : TWindow() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00492110
// TFloatWindow::`scalar deleting destructor'
TFloatWindow::~TFloatWindow() {}

// FUNCTION: IMPERIALISM 0x00492310
int TFloatWindow::GetWindowTypeTag() {
  return 'fwnd';
}

// FUNCTION: IMPERIALISM 0x00492330
void TFloatWindow::CallVoidSlotA0() {
  field98 = 0;
  if (nativeWindow50 != 0 && nativeWindow50->m_hWnd != 0) {
    SendMessageA(reinterpret_cast<HWND>(nativeWindow50->m_hWnd), 0x468, 1, controlTag);
  }
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->CallVoidSlotA0();
    }
  }
  OrphanCallChain_C2_I39_0048d900(0, 1);
}
