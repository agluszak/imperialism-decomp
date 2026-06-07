// UI wrapper class quads extracted from trade_screen.

#include "game/THQButton.h"
#include "game/ui_widget_shared.h"

int g_pClassDescTHQButton;

// FUNCTION: IMPERIALISM 0x0058b5c0
void* __cdecl CreateTHQButtonInstance(void) {
  return new THQButton();
}

// FUNCTION: IMPERIALISM 0x0058b640
void* __cdecl GetTHQButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTHQButton);
}

// FUNCTION: IMPERIALISM 0x0058b660
THQButton::THQButton() : TPictureButton() {}

// FUNCTION: IMPERIALISM 0x0058b690
THQButton::~THQButton() {}

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x0058b6e0
void __fastcall WrapperFor_thunk_NoOpUiLifecycleHook_At0058b6e0(THQButton* button) {
  short glyph = button->glyphBase84;
  thunk_NoOpUiLifecycleHook();
  button->glyph98 = 0;
  button->glyph90 = glyph;
  button->hasCommandTagResource = 0xc;
  button->timingWord92 = (short)(glyph + 1); // wait, timingWord92 was glyph92!
  button->glyph94 = (short)(glyph + 2);
  button->glyph96 = (short)(glyph + 3);
}

// FUNCTION: IMPERIALISM 0x0058b7f0
void __fastcall WrapperFor_HandleCityDialogToggleCommandOrForward_At0058b7f0(THQButton* button,
                                                                             int unusedEdx,
                                                                             int commandId) {
  (void)unusedEdx;
  TradeControl* control = reinterpret_cast<TradeControl*>(button);
  if (commandId == 0xc) {
    if (button->commandTagResourceByte == 0) { // toggleStateAt64
      control->InvokeSlot1CC(1, 1);
    }
    thunk_HandleCityDialogToggleCommandOrForward();
    return;
  }
  if (commandId != 0x1f) {
    if (commandId != 0x20) {
      thunk_HandleCityDialogToggleCommandOrForward();
      return;
    }
    control->InvokeSlot1CC(0, 1);
    return;
  }
  control->InvokeSlot1CC(1, 1);
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif
