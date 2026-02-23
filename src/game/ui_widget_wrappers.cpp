// UI wrapper class quads extracted from trade_screen.

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
unsigned int __cdecl thunk_GetActiveNationId(void);
undefined4 thunk_NoOpUiLifecycleHook(void);
undefined4 thunk_HandleCityDialogToggleCommandOrForward(void);
undefined4 thunk_HandleCursorHoverSelectionByChildHitTestAndFallback(void);
undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);
undefined4 thunk_ConstructUiClickablePictureResourceEntry(void);
undefined4 thunk_ConstructUiCommandTagResourceEntryBase(void);
undefined4 thunk_ConstructPictureResourceEntryBase(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void);

namespace {

const int kControlTagPlus = 0x706c7573;
const int kControlTagMinu = 0x6d696e75;
const unsigned int kAddrCityOrderCapabilityState = 0x006A43D8;

char g_vtblTCivilianButton;
char g_pClassDescTCivilianButton;
char g_vtblTHQButton;
char g_pClassDescTHQButton;
char g_vtblTPlacard;
char g_pClassDescTPlacard;
char g_vtblTArmyPlacard;
char g_pClassDescTArmyPlacard;
char g_vtblTNumberedArrowButton;
char g_pClassDescTNumberedArrowButton;
char g_vtblTCombatReportView;
char g_pClassDescTCombatReportView;

struct TradeControlVirtualShape {
  virtual void CtrlSlot00(void) = 0;
  virtual void CtrlSlot01(void) = 0;
  virtual void CtrlSlot02(void) = 0;
  virtual void CtrlSlot03(void) = 0;
  virtual void CtrlSlot04(void) = 0;
  virtual void CtrlSlot05(void) = 0;
  virtual void CtrlSlot06(void) = 0;
  virtual void CtrlSlot07(void) = 0;
  virtual void CtrlSlot08(void) = 0;
  virtual void CtrlSlot09(void) = 0;
  virtual void CtrlSlot10(void) = 0;
  virtual void CtrlSlot11(void) = 0;
  virtual short QueryStepValueSlot30(void) = 0;
  virtual void CtrlSlot13(void) = 0;
  virtual void CtrlSlot14(void) = 0;
  virtual void CtrlSlot15(void) = 0;
  virtual void CtrlSlot16(void) = 0;
  virtual void CtrlSlot17(void) = 0;
  virtual void CtrlSlot18(void) = 0;
  virtual void CtrlSlot19(void) = 0;
  virtual void CtrlSlot20(void) = 0;
  virtual void CtrlSlot21(void) = 0;
  virtual void CtrlSlot22(void) = 0;
  virtual void CtrlSlot23(void) = 0;
  virtual void CtrlSlot24(void) = 0;
  virtual void CtrlSlot25(void) = 0;
  virtual void CtrlSlot26(void) = 0;
  virtual void CtrlSlot27(void) = 0;
  virtual void CtrlSlot28(void) = 0;
  virtual void CtrlSlot29(void) = 0;
  virtual void CtrlSlot30(void) = 0;
  virtual void CtrlSlot31(void) = 0;
  virtual void CtrlSlot32(void) = 0;
  virtual void CtrlSlot33(void) = 0;
  virtual void CtrlSlot34(void) = 0;
  virtual void CtrlSlot35(void) = 0;
  virtual void CtrlSlot36(void) = 0;
  virtual void CtrlSlot37(void) = 0;
  virtual void CtrlSlot38(void) = 0;
  virtual void CtrlSlot39(void) = 0;
  virtual void CtrlSlot40(void) = 0;
  virtual void SetEnabledSlotA4(int enabled, int unknownFlag) = 0;
  virtual void SetStateSlotA8(int enabled, int unknownFlag) = 0;
  virtual void CtrlSlot43(void) = 0;
  virtual void CtrlSlot44(void) = 0;
  virtual void CtrlSlot45(void) = 0;
  virtual void CtrlSlot46(void) = 0;
  virtual void CtrlSlot47(void) = 0;
  virtual void CtrlSlot48(void) = 0;
  virtual void CtrlSlot49(void) = 0;
  virtual void CtrlSlot50(void) = 0;
  virtual void CtrlSlot51(void) = 0;
  virtual void CtrlSlot52(void) = 0;
  virtual void CtrlSlot53(void) = 0;
  virtual void CtrlSlot54(void) = 0;
  virtual void CtrlSlot55(void) = 0;
  virtual void CtrlSlot56(void) = 0;
  virtual void CtrlSlot57(void) = 0;
  virtual void CtrlSlot58(void) = 0;
  virtual char IsActionableSlotEC(void) = 0;
  virtual void CaptureLayoutSlotF0(int *buffer, int modeFlag) = 0;
  virtual void CaptureLayoutSlotF4(int *buffer, int modeFlag) = 0;
  virtual void RefreshSlotF8(void) = 0;
  virtual void CtrlSlot63(void) = 0;
  virtual void CtrlSlot64(void) = 0;
  virtual void CtrlSlot65(void) = 0;
  virtual void CtrlSlot66(void) = 0;
  virtual void CtrlSlot67(void) = 0;
  virtual void CtrlSlot68(void) = 0;
  virtual void UpdateAfterBitmapChangeSlot114(int unknownFlag) = 0;
  virtual void CtrlSlot70(void) = 0;
  virtual void CtrlSlot71(void) = 0;
  virtual void CtrlSlot72(void) = 0;
  virtual void CtrlSlot73(void) = 0;
  virtual void CtrlSlot74(void) = 0;
  virtual void QueryBoundsSlot12C(int *boundsBuffer) = 0;
  virtual void CtrlSlot76(void) = 0;
  virtual void CtrlSlot77(void) = 0;
  virtual void CtrlSlot78(void) = 0;
  virtual void CtrlSlot79(void) = 0;
  virtual void CtrlSlot80(void) = 0;
  virtual void CtrlSlot81(void) = 0;
  virtual void CtrlSlot82(void) = 0;
  virtual void CtrlSlot83(void) = 0;
  virtual void CtrlSlot84(void) = 0;
  virtual void CtrlSlot85(void) = 0;
  virtual void CtrlSlot86(void) = 0;
  virtual void CtrlSlot87(void) = 0;
  virtual void CtrlSlot88(void) = 0;
  virtual void CtrlSlot89(void) = 0;
  virtual void ApplyBoundsSlot168(int *boundsBuffer, int modeFlag) = 0;
  virtual void CtrlSlot91(void) = 0;
  virtual void CtrlSlot92(void) = 0;
  virtual void CtrlSlot93(void) = 0;
  virtual void CtrlSlot94(void) = 0;
  virtual void CtrlSlot95(void) = 0;
  virtual void CtrlSlot96(void) = 0;
  virtual void CtrlSlot97(void) = 0;
  virtual void CtrlSlot98(void) = 0;
  virtual void CtrlSlot99(void) = 0;
  virtual void CtrlSlot100(void) = 0;
  virtual void CtrlSlot101(void) = 0;
  virtual void CtrlSlot102(void) = 0;
  virtual void CtrlSlot103(void) = 0;
  virtual int ApplyMoveClampSlot1A0(int baseValue, int requestedValue) = 0;
  virtual void SetBarMetricSlot1A4(int value, int range) = 0;
  virtual void CtrlSlot106(void) = 0;
  virtual void SetBarMetricRatioSlot1AC(int value) = 0;
  virtual void CtrlSlot108(void) = 0;
  virtual void ApplyStyleDescriptorSlot1B4(void *descriptorBuffer, int modeFlag) = 0;
  virtual void CtrlSlot110(void) = 0;
  virtual void CtrlSlot111(void) = 0;
  virtual void CtrlSlot112(void) = 0;
  virtual void SetStyleStateSlot1C4(int stateValue, int modeFlag) = 0;
  virtual void SetBitmapSlot1C8(int bitmapIdValue, int unknownFlag) = 0;
  virtual void InvokeSlot1CC(int value, int modeFlag) = 0;
  virtual void CtrlSlot116(void) = 0;
  virtual void CtrlSlot117(void) = 0;
  virtual void CtrlSlot118(void) = 0;
  virtual void CtrlSlot119(void) = 0;
  virtual void CtrlSlot120(void) = 0;
  virtual void SetControlValueSlot1E4(int value, int updateFlag) = 0;
  virtual int QueryValueSlot1E8(void) = 0;
};

struct TradeControl {
  void *vftable;
  char pad_04[0x18];
  int controlTag;
  char pad_20[0x64];
  short bitmapId;

  __inline char IsActionable();
  __inline void SetBitmap(int bitmapIdValue, int unknownFlag);
  __inline void QueryBounds(int *boundsBuffer);
  __inline void InvokeSlotE4();
  __inline void InvokeSlot1CC(int value, int modeFlag);
};

struct CivilianButtonState {
  void *vftable;
  char pad_04[0x5c];
  int buttonTag;
};

struct HQButtonState {
  void *vftable;
  char pad_04[0x5c];
  int buttonTag;
  unsigned char toggleStateAt64;
  char pad_65[0x1f];
  short glyphBase84;
  char pad_86[0xa];
  short glyph90;
  short glyph92;
  short glyph94;
  short glyph96;
  short glyph98;
  char pad_9a[2];
};

struct PlacardState {
  void *vftable;
  char pad_04[0x8c];
  short placardValue;
};

struct NumberedArrowButtonState {
  void *vftable;
  char pad_04[0x34];
  int width38;
  char pad_3c[0x12];
  short hoverTag4e;
  char pad_50[0x34];
  short value84;
  short value86;
};

struct CombatReportViewState {
  void *vftable;
  char pad_04[0x9c];
};

static __inline TradeControlVirtualShape *AsTradeControlVirtualShape(TradeControl *control)
{
  return reinterpret_cast<TradeControlVirtualShape *>(control);
}

class TradeScreenRuntimeBridge {
public:
  static __inline void ConstructUiClickablePictureResourceEntry(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(
        ::thunk_ConstructUiClickablePictureResourceEntry)(self);
  }

  static __inline void ConstructUiCommandTagResourceEntryBase(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(
        ::thunk_ConstructUiCommandTagResourceEntryBase)(self);
  }

  static __inline void ConstructPictureResourceEntryBase(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_ConstructPictureResourceEntryBase)(self);
  }

  static __inline void DestructCityDialogSharedBaseState(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_DestructCityDialogSharedBaseState)(self);
  }
};

__inline char TradeControl::IsActionable()
{
  return AsTradeControlVirtualShape(this)->IsActionableSlotEC();
}

__inline void TradeControl::SetBitmap(int bitmapIdValue, int unknownFlag)
{
  AsTradeControlVirtualShape(this)->SetBitmapSlot1C8(bitmapIdValue, unknownFlag);
}

__inline void TradeControl::QueryBounds(int *boundsBuffer)
{
  AsTradeControlVirtualShape(this)->QueryBoundsSlot12C(boundsBuffer);
}

__inline void TradeControl::InvokeSlotE4()
{
  AsTradeControlVirtualShape(this)->CtrlSlot57();
}

__inline void TradeControl::InvokeSlot1CC(int value, int modeFlag)
{
  AsTradeControlVirtualShape(this)->InvokeSlot1CC(value, modeFlag);
}

static __inline short QueryActiveNationId(void)
{
  return (short)thunk_GetActiveNationId();
}

}  // namespace

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







// FUNCTION: IMPERIALISM 0x0058BE30
PlacardState *__cdecl CreateTArmyPlacardInstance(void)
{
  PlacardState *placard = reinterpret_cast<PlacardState *>(AllocateWithFallbackHandler(0x94));
  if (placard != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
    placard->vftable = reinterpret_cast<void *>(&g_vtblTArmyPlacard);
    placard->placardValue = (short)0xffff;
  }
  return placard;
}







// FUNCTION: IMPERIALISM 0x0058BEB0
void *__cdecl GetTArmyPlacardClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTArmyPlacard);
}







// FUNCTION: IMPERIALISM 0x0058BED0
PlacardState *__fastcall ConstructTArmyPlacardBaseState(PlacardState *placard)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
  placard->vftable = reinterpret_cast<void *>(&g_vtblTArmyPlacard);
  placard->placardValue = (short)0xffff;
  return placard;
}







// FUNCTION: IMPERIALISM 0x0058BF00
PlacardState *__fastcall DestructTArmyPlacardAndMaybeFree(
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






// FUNCTION: IMPERIALISM 0x0058BF50
void __fastcall WrapperFor_GetActiveNationId_At0058bf50(
    PlacardState *placard, int unusedEdx, short requestedValue)
{
  (void)unusedEdx;
  short nationId = (short)QueryActiveNationId();
  int controlIndex = *reinterpret_cast<int *>(reinterpret_cast<char *>(placard) + 0x1c);
  char *cityOrderBase = *reinterpret_cast<char **>(kAddrCityOrderCapabilityState);
  short baseSprite = *reinterpret_cast<short *>(
      cityOrderBase + 0x1f2d3b76 + (controlIndex + (int)nationId * 10) * 2);

  if (requestedValue != placard->placardValue) {
    short sprite = (short)(baseSprite + 0x4c4);
    if (requestedValue < 1) {
      sprite = (short)(baseSprite + 0x4e2);
    }
    reinterpret_cast<TradeControl *>(placard)->SetBitmap((int)sprite, 1);
    reinterpret_cast<TradeControl *>(placard)->InvokeSlotE4();
  }
  placard->placardValue = requestedValue;
}






// FUNCTION: IMPERIALISM 0x0058C140
void __fastcall HandlePlusMinusCommandAndInvokeVslot1CC(
    PlacardState *placard, int unusedEdx, int *arg1, int *arg2)
{
  (void)unusedEdx;
  (void)arg1;
  TradeControl *control = reinterpret_cast<TradeControl *>(placard);
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





// FUNCTION: IMPERIALISM 0x0058C1E0
NumberedArrowButtonState *__cdecl CreateTNumberedArrowButtonInstance(void)
{
  NumberedArrowButtonState *button = reinterpret_cast<NumberedArrowButtonState *>(
      AllocateWithFallbackHandler(0x88));
  if (button != 0) {
    TradeScreenRuntimeBridge::ConstructUiCommandTagResourceEntryBase(button);
    button->vftable = reinterpret_cast<void *>(&g_vtblTNumberedArrowButton);
    button->value84 = 0;
    button->value86 = 0;
  }
  return button;
}





// FUNCTION: IMPERIALISM 0x0058C280
void *__cdecl GetTNumberedArrowButtonClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTNumberedArrowButton);
}





// FUNCTION: IMPERIALISM 0x0058C2A0
NumberedArrowButtonState *__fastcall
ConstructTNumberedArrowButtonBaseState(NumberedArrowButtonState *button)
{
  TradeScreenRuntimeBridge::ConstructUiCommandTagResourceEntryBase(button);
  button->vftable = reinterpret_cast<void *>(&g_vtblTNumberedArrowButton);
  button->value84 = 0;
  button->value86 = 0;
  return button;
}





// FUNCTION: IMPERIALISM 0x0058C2E0
NumberedArrowButtonState *__fastcall DestructTNumberedArrowButtonAndMaybeFree(
    NumberedArrowButtonState *button, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}




// FUNCTION: IMPERIALISM 0x0058C330
void __fastcall OrphanCallChain_C1_I08_0058c330(
    NumberedArrowButtonState *button, int unusedEdx, short value84, char refreshFlag)
{
  (void)unusedEdx;
  button->value84 = value84;
  if (refreshFlag != '\0') {
    reinterpret_cast<TradeControl *>(button)->InvokeSlotE4();
  }
}




// FUNCTION: IMPERIALISM 0x0058C360
void __fastcall OrphanCallChain_C2_I23_0058c360(
    NumberedArrowButtonState *button, int unusedEdx, short value86, char refreshFlag)
{
  (void)unusedEdx;
  int bounds[4];
  if (button->value86 != value86) {
    if (refreshFlag != '\0') {
      reinterpret_cast<TradeControl *>(button)->InvokeSlotE4();
      reinterpret_cast<TradeControl *>(button)->QueryBounds(bounds);
    }
    button->value86 = value86;
  }
}




// FUNCTION: IMPERIALISM 0x0058C7C0
void __fastcall WrapperFor_thunk_HandleCursorHoverSelectionByChildHitTestAndFallback_At0058c7c0(
    NumberedArrowButtonState *button, int unusedEdx, int *cursorPoint, int hitArg)
{
  (void)unusedEdx;
  TradeControl *control = reinterpret_cast<TradeControl *>(button);
  if (control->IsActionable() != '\0') {
    if (cursorPoint[1] < button->width38 / 2) {
      button->hoverTag4e = 0x100;
      reinterpret_cast<void (__fastcall *)(NumberedArrowButtonState *, int *, int)>(
          ::thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(button, cursorPoint, hitArg);
      return;
    }
    button->hoverTag4e = (short)0xffff;
  }
  reinterpret_cast<void (__fastcall *)(NumberedArrowButtonState *, int *, int)>(
      ::thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(button, cursorPoint, hitArg);
}





// FUNCTION: IMPERIALISM 0x0058C830
CombatReportViewState *__cdecl CreateTCombatReportViewInstance(void)
{
  CombatReportViewState *view = reinterpret_cast<CombatReportViewState *>(
      AllocateWithFallbackHandler(0xa0));
  if (view != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(view);
    view->vftable = reinterpret_cast<void *>(&g_vtblTCombatReportView);
  }
  return view;
}





// FUNCTION: IMPERIALISM 0x0058C8B0
void *__cdecl GetTCombatReportViewClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTCombatReportView);
}





// FUNCTION: IMPERIALISM 0x0058C8D0
CombatReportViewState *__fastcall ConstructTCombatReportViewBaseState(CombatReportViewState *view)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(view);
  view->vftable = reinterpret_cast<void *>(&g_vtblTCombatReportView);
  return view;
}





// FUNCTION: IMPERIALISM 0x0058C900
CombatReportViewState *__fastcall DestructTCombatReportViewAndMaybeFree(
    CombatReportViewState *view, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(view);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)view);
  }
  return view;
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif
