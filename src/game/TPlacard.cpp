// UI wrapper class quads extracted from trade_screen.

#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif









// FUNCTION: IMPERIALISM 0x0058B960
PlacardState *__cdecl CreateTPlacardInstance(void)
{
  PlacardState *placard = reinterpret_cast<PlacardState *>(AllocateWithFallbackHandler(0x94));
  if (placard != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
    placard->vftable = reinterpret_cast<void *>(&g_vtblTPlacard);
    placard->placardValue = 0;
  }
  return placard;
}









// FUNCTION: IMPERIALISM 0x0058B9F0
void *__cdecl GetTPlacardClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTPlacard);
}









// FUNCTION: IMPERIALISM 0x0058BA10
PlacardState *__fastcall ConstructTPlacardBaseState(PlacardState *placard)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
  placard->vftable = reinterpret_cast<void *>(&g_vtblTPlacard);
  placard->placardValue = 0;
  return placard;
}









// FUNCTION: IMPERIALISM 0x0058BA40
PlacardState *__fastcall DestructTPlacardAndMaybeFree(
    PlacardState *placard, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(placard);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)placard);
  }
  return placard;
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif
