#pragma once

// Shared UI-wrapper scaffolding extracted from widget class files.

#include "decomp_types.h"
#include "game/TControl.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
unsigned int __cdecl thunk_GetActiveNationId(void);
undefined4 thunk_NoOpUiLifecycleHook(void);
undefined4 thunk_HandleCityDialogToggleCommandOrForward(void);
undefined4 thunk_HandleCursorHoverSelectionByChildHitTestAndFallback(void);
undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);
undefined4 ConstructTUberClusterBaseState(void);
undefined4 thunk_ConstructUiResourceEntryType4B0C0(void);
undefined4 thunk_ConstructUiClickablePictureResourceEntry(void);
undefined4 thunk_ConstructPictureResourceEntryBase(void);
void __fastcall InitializeTradeMoveAndBarControls(void* context, int unusedEdx = 0,
                                                  unsigned int styleSeed = 0);
void __fastcall HandleTradeMoveControlAdjustment(void* context, int commandId, void* eventArg,
                                                 int eventExtra);
undefined4 thunk_GetCityBuildingProductionValueBySlot(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void);

namespace {

static const int kControlTagPlus = 0x706c7573;
static const int kControlTagMinu = 0x6d696e75;
static const unsigned int kAddrCityOrderCapabilityState = 0x006A43D8;

// GLOBAL: IMPERIALISM 0x666da8
static char g_vtblTCivilianButton;
// GLOBAL: IMPERIALISM 0x663040
static char g_pClassDescTCivilianButton;
// GLOBAL: IMPERIALISM 0x666fe0
static char g_vtblTHQButton;
// GLOBAL: IMPERIALISM 0x663058
static char g_pClassDescTHQButton;
// GLOBAL: IMPERIALISM 0x667218
static char g_vtblTPlacard;
// GLOBAL: IMPERIALISM 0x663070
static char g_pClassDescTPlacard;
// GLOBAL: IMPERIALISM 0x667448
static char g_vtblTArmyPlacard;
// GLOBAL: IMPERIALISM 0x663088
static char g_pClassDescTArmyPlacard;
// GLOBAL: IMPERIALISM 0x667678
static char g_vtblTNumberedArrowButton;
// GLOBAL: IMPERIALISM 0x6630a0
static char g_pClassDescTNumberedArrowButton;
// GLOBAL: IMPERIALISM 0x6678a0
static char g_vtblTCombatReportView;
// GLOBAL: IMPERIALISM 0x6630b8
static char g_pClassDescTCombatReportView;

struct TradeControl {
  char pad_04[0x18];
  int controlTag;
  char pad_20[0x64];
  short bitmapId;

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
  virtual void SetControlValueSlot2C(int value) = 0;
  virtual short QueryStepValueSlot30(void) = 0;
  virtual void CtrlSlot13(void) = 0;
  virtual void CtrlSlot14(void) = 0;
  virtual void CtrlSlot15(void) = 0;
  virtual void CtrlSlot16(int commandId, void* eventArg, int eventExtra) = 0;
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
  virtual void CaptureLayoutSlotF0(int* buffer, int modeFlag) = 0;
  virtual void CaptureLayoutSlotF4(int* buffer, int modeFlag) = 0;
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
  virtual void QueryBoundsSlot12C(int* boundsBuffer) = 0;
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
  virtual void ApplyBoundsSlot168(int* boundsBuffer, int modeFlag) = 0;
  virtual char CtrlSlot91(void* dispatchArg) = 0;
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
  virtual void ApplyStyleDescriptorSlot1B4(void* descriptorBuffer, int modeFlag) = 0;
  virtual void CtrlSlot110(void) = 0;
  virtual void CtrlSlot111(void) = 0;
  virtual void CtrlSlot112(void) = 0;
  virtual void SetStyleStateSlot1C4(int stateValue, int modeFlag) = 0;
  virtual void SetBitmapSlot1C8(int bitmapIdValue, int unknownFlag) = 0;
  virtual void InvokeSlot1CCVirtual(int value, int modeFlag) = 0;
  virtual void CtrlSlot116(void) = 0;
  virtual void CtrlSlot117(void) = 0;
  virtual void CtrlSlot118(void) = 0;
  virtual void CtrlSlot119(void) = 0;
  virtual void CtrlSlot120(void) = 0;
  virtual void SetControlValueSlot1E4(int value, int updateFlag) = 0;
  virtual int QueryValueSlot1E8(void) = 0;

  __inline int QueryValue();
  __inline short QueryStepValue();
  __inline char IsActionable();
  __inline void SetEnabledSingle(int enabled);
  __inline void SetEnabledPair(int enabled, int unknownFlag);
  __inline void SetStatePair(int enabled, int unknownFlag);
  __inline void SetBitmap(int bitmapIdValue, int unknownFlag);
  __inline void SetBarMetric(int value, int range);
  __inline void SetBarMetricRatio(int value);
  __inline int ApplyMoveClamp(int baseValue, int requestedValue);
  __inline void SetControlValue(int value, int updateFlag);
  __inline void SetControlValueRaw(int value);
  __inline void ApplyStyleDescriptor(void* descriptorBuffer, int modeFlag);
  __inline void SetStyleState(int stateValue, int modeFlag);
  __inline void QueryBounds(int* boundsBuffer);
  __inline void ApplyBounds(int* boundsBuffer, int modeFlag);
  __inline void CaptureLayoutF0(int* buffer, int modeFlag);
  __inline void CaptureLayout(int* buffer, int modeFlag);
  __inline void CaptureLayoutPreset11_14();
  __inline void Refresh();
  __inline void UpdateAfterBitmapChange(int unknownFlag);
  __inline void InvokeSlotE4();
  __inline void InvokeSlot1CC(int value, int modeFlag);
  __inline void InvokeSlot13C();
  __inline void InvokeSlot1A8();
};

struct CivilianButtonState {
  void* vftable;
  char pad_04[0x5c];
  int buttonTag;
};

struct HQButtonState {
  void* vftable;
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
  void* vftable;
  char pad_04[0x8c];
  short placardValue;

  void WrapperFor_thunk_NoOpUiLifecycleHook_At0058bab0();
  void WrapperFor_thunk_InvalidateCityDialogRectRegion_At0058bb50(int arg1, int arg2);
  void RenderPlacardValueTextWithShadow();
};

struct NumberedArrowButtonState {
  void* vftable;
  char pad_04[0x34];
  int width38;
  char pad_3c[0x12];
  short hoverTag4e;
  char pad_50[0x34];
  short value84;
  short value86;
};

struct CombatReportViewState {
  void* vftable;
  char pad_04[0x9c];
};

class TradeScreenRuntimeBridge {
public:
  static __inline void ConstructTUberClusterBaseState(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::ConstructTUberClusterBaseState)(self);
  }

  static __inline void ConstructUiResourceEntryBase(void* self) {
    reinterpret_cast<TView*>(self)->thunk_ConstructUiResourceEntryBase();
  }

  static __inline void ConstructUiResourceEntryType4B0C0(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructUiResourceEntryType4B0C0)(self);
  }

  static __inline void ConstructUiClickablePictureResourceEntry(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructUiClickablePictureResourceEntry)(
        self);
  }

  static __inline void ConstructUiCommandTagResourceEntryBase(void* self) {
    reinterpret_cast<TControl*>(self)->ConstructUiCommandTagResourceEntryBase();
  }

  static __inline void ConstructPictureResourceEntryBase(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructPictureResourceEntryBase)(self);
  }

  static __inline void InitializeTradeMoveAndBarControls(void* self) {
    ::InitializeTradeMoveAndBarControls(self);
  }

  static __inline int GetCityBuildingProductionValueBySlot(void* cityState, short slot) {
    return (int)reinterpret_cast<undefined4(__fastcall*)(void*, short)>(
        ::thunk_GetCityBuildingProductionValueBySlot)(cityState, slot);
  }

  static __inline void DestructCityDialogSharedBaseState(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_DestructCityDialogSharedBaseState)(self);
  }
};

__inline int TradeControl::QueryValue() {
  return this->QueryValueSlot1E8();
}

__inline short TradeControl::QueryStepValue() {
  return this->QueryStepValueSlot30();
}

__inline char TradeControl::IsActionable() {
  return this->IsActionableSlotEC();
}

__inline void TradeControl::SetEnabledSingle(int enabled) {
  this->SetEnabledSlotA4(enabled, 1);
}

__inline void TradeControl::SetEnabledPair(int enabled, int unknownFlag) {
  this->SetEnabledSlotA4(enabled, unknownFlag);
}

__inline void TradeControl::SetStatePair(int enabled, int unknownFlag) {
  this->SetStateSlotA8(enabled, unknownFlag);
}

__inline void TradeControl::SetBitmap(int bitmapIdValue, int unknownFlag) {
  this->SetBitmapSlot1C8(bitmapIdValue, unknownFlag);
}

__inline void TradeControl::SetBarMetric(int value, int range) {
  this->SetBarMetricSlot1A4(value, range);
}

__inline void TradeControl::SetBarMetricRatio(int value) {
  this->SetBarMetricRatioSlot1AC(value);
}

__inline int TradeControl::ApplyMoveClamp(int baseValue, int requestedValue) {
  return this->ApplyMoveClampSlot1A0(baseValue, requestedValue);
}

__inline void TradeControl::SetControlValue(int value, int updateFlag) {
  this->SetControlValueSlot1E4(value, updateFlag);
}

__inline void TradeControl::SetControlValueRaw(int value) {
  this->SetControlValueSlot2C(value);
}

__inline void TradeControl::ApplyStyleDescriptor(void* descriptorBuffer, int modeFlag) {
  this->ApplyStyleDescriptorSlot1B4(descriptorBuffer, modeFlag);
}

__inline void TradeControl::SetStyleState(int stateValue, int modeFlag) {
  this->SetStyleStateSlot1C4(stateValue, modeFlag);
}

__inline void TradeControl::QueryBounds(int* boundsBuffer) {
  this->QueryBoundsSlot12C(boundsBuffer);
}

__inline void TradeControl::ApplyBounds(int* boundsBuffer, int modeFlag) {
  this->ApplyBoundsSlot168(boundsBuffer, modeFlag);
}

__inline void TradeControl::CaptureLayoutF0(int* buffer, int modeFlag) {
  this->CaptureLayoutSlotF0(buffer, modeFlag);
}

__inline void TradeControl::CaptureLayout(int* buffer, int modeFlag) {
  this->CaptureLayoutSlotF4(buffer, modeFlag);
}

__inline void TradeControl::CaptureLayoutPreset11_14() {
  int layoutCapture[2] = {0x11, 0x14};
  CaptureLayout(layoutCapture, 1);
}

__inline void TradeControl::Refresh() {
  this->RefreshSlotF8();
}

__inline void TradeControl::UpdateAfterBitmapChange(int unknownFlag) {
  this->UpdateAfterBitmapChangeSlot114(unknownFlag);
}

__inline void TradeControl::InvokeSlotE4() {
  this->CtrlSlot57();
}

__inline void TradeControl::InvokeSlot1CC(int value, int modeFlag) {
  this->InvokeSlot1CCVirtual(value, modeFlag);
}

__inline void TradeControl::InvokeSlot13C() {
  this->CtrlSlot79();
}

__inline void TradeControl::InvokeSlot1A8() {
  this->CtrlSlot106();
}

static __inline short QueryActiveNationId(void) {
  return (short)thunk_GetActiveNationId();
}

} // namespace
