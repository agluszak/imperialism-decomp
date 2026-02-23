// UI wrapper class quads extracted from trade_screen.

#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif



// FUNCTION: IMPERIALISM 0x0058B340
CivilianButtonState *__cdecl CreateTCivilianButtonInstance(void)
{
  CivilianButtonState *button = reinterpret_cast<CivilianButtonState *>(
      AllocateWithFallbackHandler(0xa0));
  if (button != 0) {
    TradeScreenRuntimeBridge::ConstructUiClickablePictureResourceEntry(button);
    button->vftable = reinterpret_cast<void *>(&g_vtblTCivilianButton);
    button->buttonTag = 0xc;
  }
  return button;
}









// FUNCTION: IMPERIALISM 0x0058B3C0
void *__cdecl GetTCivilianButtonClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTCivilianButton);
}









// FUNCTION: IMPERIALISM 0x0058B3E0
CivilianButtonState *__fastcall ConstructTCivilianButtonBaseState(CivilianButtonState *button)
{
  TradeScreenRuntimeBridge::ConstructUiClickablePictureResourceEntry(button);
  button->vftable = reinterpret_cast<void *>(&g_vtblTCivilianButton);
  button->buttonTag = 0xc;
  return button;
}









// FUNCTION: IMPERIALISM 0x0058B410
CivilianButtonState *__fastcall DestructTCivilianButtonAndMaybeFree(
    CivilianButtonState *button, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(button);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif
