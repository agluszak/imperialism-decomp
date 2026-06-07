#include "game/T2PictToggleButton.h"

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

namespace {

// GLOBAL: IMPERIALISM 0x662e78
char g_pClassDescT2PictToggleButton;

} // namespace

// FUNCTION: IMPERIALISM 0x00584890
T2PictToggleButton* __cdecl CreateT2PictToggleButtonInstance(void) {
  return new T2PictToggleButton();
}

// FUNCTION: IMPERIALISM 0x00584910
void* __cdecl GetT2PictToggleButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescT2PictToggleButton);
}

// FUNCTION: IMPERIALISM 0x00584930
T2PictToggleButton::T2PictToggleButton() : TToggleButton() {}

// FUNCTION: IMPERIALISM 0x00584960
T2PictToggleButton* __fastcall DestructT2PictToggleButtonAndMaybeFree(T2PictToggleButton* button,
                                                                      int unusedEdx,
                                                                      unsigned char freeSelfFlag) {
  (void)unusedEdx;
  button->~T2PictToggleButton();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}

T2PictToggleButton::~T2PictToggleButton() {}
