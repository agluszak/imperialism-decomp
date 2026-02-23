// UI wrapper class quads extracted from trade_screen.

#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif









// FUNCTION: IMPERIALISM 0x0058B5C0
HQButtonState *__cdecl CreateTHQButtonInstance(void)
{
  HQButtonState *button = reinterpret_cast<HQButtonState *>(AllocateWithFallbackHandler(0x9c));
  if (button != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(button);
    button->vftable = reinterpret_cast<void *>(&g_vtblTHQButton);
  }
  return button;
}









// FUNCTION: IMPERIALISM 0x0058B640
void *__cdecl GetTHQButtonClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTHQButton);
}









// FUNCTION: IMPERIALISM 0x0058B660
HQButtonState *__fastcall ConstructTHQButtonBaseState(HQButtonState *button)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(button);
  button->vftable = reinterpret_cast<void *>(&g_vtblTHQButton);
  return button;
}









// FUNCTION: IMPERIALISM 0x0058B690
HQButtonState *__fastcall DestructTHQButtonAndMaybeFree(
    HQButtonState *button, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(button);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}








// FUNCTION: IMPERIALISM 0x0058B6E0
void __fastcall WrapperFor_thunk_NoOpUiLifecycleHook_At0058b6e0(HQButtonState *button)
{
  short glyph = button->glyphBase84;
  thunk_NoOpUiLifecycleHook();
  button->glyph98 = 0;
  button->glyph90 = glyph;
  button->buttonTag = 0xc;
  button->glyph92 = (short)(glyph + 1);
  button->glyph94 = (short)(glyph + 2);
  button->glyph96 = (short)(glyph + 3);
}








// FUNCTION: IMPERIALISM 0x0058B7F0
void __fastcall WrapperFor_HandleCityDialogToggleCommandOrForward_At0058b7f0(
    HQButtonState *button, int unusedEdx, int commandId)
{
  (void)unusedEdx;
  TradeControl *control = reinterpret_cast<TradeControl *>(button);
  if (commandId == 0xc) {
    if (button->toggleStateAt64 == 0) {
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
