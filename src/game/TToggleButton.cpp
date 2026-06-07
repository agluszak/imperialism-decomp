#include "game/TToggleButton.h"

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

namespace {

// GLOBAL: IMPERIALISM 0x65e598
char g_pClassDescTToggleButton;

} // namespace

// FUNCTION: IMPERIALISM 0x00571050
TToggleButton* __cdecl CreateTToggleButtonInstance(void) {
  return new TToggleButton();
}

// FUNCTION: IMPERIALISM 0x005710d0
void* __cdecl GetTToggleButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTToggleButton);
}

// FUNCTION: IMPERIALISM 0x005710f0
TToggleButton::TToggleButton() : TPictureResourceEntryBase() {}

// FUNCTION: IMPERIALISM 0x00571120
TToggleButton* __fastcall DestructTToggleButtonAndMaybeFree(TToggleButton* button, int unusedEdx,
                                                            unsigned char freeSelfFlag) {
  (void)unusedEdx;
  button->~TToggleButton();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}

TToggleButton::~TToggleButton() {}
