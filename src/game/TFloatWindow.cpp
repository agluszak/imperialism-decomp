#include "game/TFloatWindow.h"
#include "game/TDialogBehavior.h"
#include "game/mfc.h"

extern "C" CRuntimeClass PTR_s_TFloatWindow_006496d8;
extern CPtrList g_LiveViewRegistry;

extern "C" void __fastcall SetUiColorDescriptorGoldTriplet(int param_1, int param_2, int param_3, int param_4);

// FUNCTION: IMPERIALISM 0x00487400
void __fastcall SetUiColorDescriptorGoldTriplet(int param_1, int param_2, int param_3, int param_4) {
  *reinterpret_cast<unsigned char*>(param_1 + 0x10) = static_cast<unsigned char>(param_2);
  *reinterpret_cast<int*>(param_1 + 4) = 0x646c6f67; // 'gold'
  *reinterpret_cast<int*>(param_1 + 0x14) = param_3;
  *reinterpret_cast<int*>(param_1 + 0x18) = param_4;
}

// FUNCTION: IMPERIALISM 0x00491e00
TView* TFloatWindow::CreateTFloatWindowInstance() {
  return new TFloatWindow();
}

// FUNCTION: IMPERIALISM 0x00491f90
CRuntimeClass* TFloatWindow::GetRuntimeClass() const {
  return &PTR_s_TFloatWindow_006496d8;
}

// FUNCTION: IMPERIALISM 0x00491fb0
TFloatWindow::TFloatWindow() : TWindow() {
  g_LiveViewRegistry.AddTail(this);
  SetUiColorDescriptorGoldTriplet(reinterpret_cast<int>(this), 0x20202020, 0x20202020, 0x20202020);
  field64 = this;
  GetEmbeddedDialogBehavior()->SetDword08(reinterpret_cast<int>(this));
}

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
