// UI wrapper class quads extracted from trade_screen.

#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x0058BE30
PlacardState* __cdecl CreateTArmyPlacardInstance(void) {
  PlacardState* placard = reinterpret_cast<PlacardState*>(AllocateWithFallbackHandler(0x94));
  if (placard != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
    placard->vftable = reinterpret_cast<void*>(&g_vtblTArmyPlacard);
    placard->placardValue = (short)0xffff;
  }
  return placard;
}

// FUNCTION: IMPERIALISM 0x0058BEB0
void* __cdecl GetTArmyPlacardClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTArmyPlacard);
}

// FUNCTION: IMPERIALISM 0x0058BED0
PlacardState* __fastcall ConstructTArmyPlacardBaseState(PlacardState* placard) {
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
  placard->vftable = reinterpret_cast<void*>(&g_vtblTArmyPlacard);
  placard->placardValue = (short)0xffff;
  return placard;
}

// FUNCTION: IMPERIALISM 0x0058BF00
PlacardState* __fastcall DestructTArmyPlacardAndMaybeFree(PlacardState* placard, int unusedEdx,
                                                          unsigned char freeSelfFlag) {
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

// FUNCTION: IMPERIALISM 0x0058BF50
void __fastcall WrapperFor_GetActiveNationId_At0058bf50(PlacardState* placard, int unusedEdx,
                                                        short requestedValue) {
  (void)unusedEdx;
  short nationId = (short)QueryActiveNationId();
  int controlIndex = *reinterpret_cast<int*>(reinterpret_cast<char*>(placard) + 0x1c);
  char* cityOrderBase = *reinterpret_cast<char**>(kAddrCityOrderCapabilityState);
  short baseSprite = *reinterpret_cast<short*>(cityOrderBase + 0x1f2d3b76 +
                                               (controlIndex + (int)nationId * 10) * 2);

  if (requestedValue != placard->placardValue) {
    short sprite = (short)(baseSprite + 0x4c4);
    if (requestedValue < 1) {
      sprite = (short)(baseSprite + 0x4e2);
    }
    reinterpret_cast<TradeControl*>(placard)->SetBitmap((int)sprite, 1);
    reinterpret_cast<TradeControl*>(placard)->InvokeSlotE4();
  }
  placard->placardValue = requestedValue;
}

// FUNCTION: IMPERIALISM 0x0058C140
void __fastcall HandlePlusMinusCommandAndInvokeVslot1CC(PlacardState* placard, int unusedEdx,
                                                        int* arg1, int* arg2) {
  (void)unusedEdx;
  (void)arg1;
  TradeControl* control = reinterpret_cast<TradeControl*>(placard);
  if (arg2[7] == kControlTagPlus) {
    int updatedValue = (int)ActivateFirstActiveTacticalUnitByCategoryAtTile();
    control->InvokeSlot1CC(updatedValue, 1);
    return;
  }
  if (arg2[7] == kControlTagMinu) {
    int updatedValue = (int)ActivateFirstIdleTacticalUnitByCategoryAtTile();
    control->InvokeSlot1CC(updatedValue, 1);
  }
}
