#include "game/TAmtBar.h"
// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

// GHIDRA_NAME ClampAndApplyTradeMoveValue
// GHIDRA_PROTO void __cdecl ClampAndApplyTradeMoveValue(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Clamps requested move value and applies through control vfunc +0x1A0; enforces
// nonzero fallback when move/sell controls are both at zero edge case. GHIDRA_COMMENT_END
/* Clamps requested move value and applies through control vfunc +0x1A0; enforces nonzero fallback
   when move/sell controls are both at zero edge case. */

// FUNCTION: IMPERIALISM 0x00588950
void TradeMoveControlState::ClampAndApplyTradeMoveValue(int* requestedValuePtr) {
  int requestedValue = *requestedValuePtr;
  int baseValue = 0;
  if (barStepsRaw < 1 || (barRangeRaw / ((int)barStepsRaw << 1) <= *requestedValuePtr)) {
    baseValue = requestedValue;
  }

  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this);
  int appliedValue = moveControl->ApplyMoveClamp(baseValue, (short)requestedValue);
  void* owner = ownerContext;
  if (((short)appliedValue == 0) && requestedValue != 0) {
    TAmtBar* fallbackControl = reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(owner)->ResolveControlByTag(kControlTagMove));
    if (fallbackControl == 0) {
      fallbackControl = reinterpret_cast<TView*>(owner)->ResolveControlByTag(kControlTagSell);
    }
    if (fallbackControl != 0 && fallbackControl->QueryValue() == 0) {
      appliedValue = 1;
    }
  }

  reinterpret_cast<TUberCluster*>(owner)->ApplyMoveValue(appliedValue);
}

// FUNCTION: IMPERIALISM 0x00588a30
TShipyardCluster* __cdecl CreateTradeMoveStepControlPanel(void) {
  TShipyardCluster* cluster =
      reinterpret_cast<TShipyardCluster*>(AllocateWithFallbackHandler(0x90));
  if (cluster != 0) {
    new (cluster) TUberCluster();
    cluster->vftable = reinterpret_cast<void*>(kVtableTIndustryCluster);
    cluster->field_88 = 0;
  }
  return cluster;
}

// GHIDRA_NAME TIndustryCluster::GetTIndustryClusterClassNamePointer
// GHIDRA_PROTO void * __cdecl GetTIndustryClusterClassNamePointer(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns class descriptor pointer for TIndustryCluster.
// GHIDRA_COMMENT_END
/* Returns class descriptor pointer for TIndustryCluster. */

// FUNCTION: IMPERIALISM 0x00588ad0
void* __cdecl GetTIndustryClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTIndustryCluster);
}

// GHIDRA_NAME ConstructTradeMoveStepControlPanel
// GHIDRA_PROTO void __cdecl ConstructTradeMoveStepControlPanel(void)

// FUNCTION: IMPERIALISM 0x00588af0
void __fastcall ConstructTradeMoveStepControlPanel(TShipyardCluster* cluster) {
  new (cluster) TUberCluster();
  cluster->vftable = reinterpret_cast<void*>(kVtableTIndustryCluster);
  cluster->field_88 = 0;
}

// GHIDRA_NAME TIndustryCluster::DestructTIndustryClusterMaybeFree
// GHIDRA_PROTO void __cdecl DestructTIndustryClusterMaybeFree(void)

// FUNCTION: IMPERIALISM 0x00588b20
void __fastcall DestructTIndustryClusterMaybeFree(TShipyardCluster* cluster, int unusedEdx,
                                                  unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)cluster);
  }
}

// FUNCTION: IMPERIALISM 0x00588b70
void __fastcall
SyncTradeCommoditySelectionWithActiveNationAndInitControls(TradeMovePanelContext* context,
                                                           int unusedEdx, int styleSeed) {
  (void)unusedEdx;
  short tagIndex = 0;
  short activeNationId = thunk_GetActiveNationId();
  NationState* activeNationState = GetNationStateBySlot(activeNationId);
  NationCityTradeState* cityState = activeNationState == 0 ? 0 : activeNationState->cityState;

  int mappedSummaryTag = GetTradeSummarySelectionTagByIndex(0);
  while (mappedSummaryTag != context->summaryTag) {
    tagIndex = (short)(tagIndex + 1);
    mappedSummaryTag = GetTradeSummarySelectionTagByIndex(tagIndex);
  }

  TradeCommodityMetricRecord* selectedMetricRecord = reinterpret_cast<TradeCommodityMetricRecord*>(
      *reinterpret_cast<int*>(reinterpret_cast<char*>(cityState) + (int)tagIndex * 4 + 0xe4));
  context->selectedMetricControl = reinterpret_cast<TAmtBar*>(selectedMetricRecord);
  context->selectedMetricValue =
      (short)(int)reinterpret_cast<int(__fastcall*)(void*, short)>(thunk_GetCityBuildingProductionValueBySlot)(
          cityState, *reinterpret_cast<short*>(reinterpret_cast<char*>(selectedMetricRecord) + 0x52));

  reinterpret_cast<void(__fastcall*)(TradeMovePanelContext*, int, unsigned int)>(
      thunk_InitializeTradeMoveAndBarControls)(context, 0, (unsigned int)styleSeed);
  reinterpret_cast<TUberCluster*>(context)->NotifyControlSelectionChange(reinterpret_cast<void*>(*reinterpret_cast<short*>(reinterpret_cast<char*>(selectedMetricRecord) + 4)), 1);
}

// GHIDRA_NAME OrphanCallChain_C1_I06_00588c30
// GHIDRA_PROTO undefined OrphanCallChain_C1_I06_00588c30()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=6
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=6 */

// FUNCTION: IMPERIALISM 0x00588c30
void TIndustryCluster::ApplyMoveValue(int value) {
  reinterpret_cast<TUberCluster*>(reinterpret_cast<TradeMovePanelContext*>(this))->NotifyControlSelectionChange(reinterpret_cast<void*>(value), 0);
}

// FUNCTION: IMPERIALISM 0x00588c60
int TIndustryCluster::NotifyControlSelectionChange(void* dragValuePtr, int updateFlag) {
  int dragValue = (int)dragValuePtr;
  // ORIG_CALLCONV: __thiscall
  TAmtBar* selectedControl = reinterpret_cast<TradeMovePanelContext*>(this)->selectedMetricControl;
  short previousValue = ReadControlValueFieldPlus4(selectedControl);
  if (selectedControl != 0) {
    selectedControl->SetControlValue(dragValue);
  }

  if (((char)updateFlag == 0) && (ReadControlValueFieldPlus4(selectedControl) == previousValue)) {
    return 0;
  }

  TAmtBar* moveControl = reinterpret_cast<TView*>(reinterpret_cast<TradeMovePanelContext*>(this))->ResolveControlByTag(kControlTagMove);
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xb42);
  }

  moveControl->SetControlValue((int)ReadControlValueFieldPlus4(selectedControl), 0);

  RECT moveBoundsRect;
  RECT moveInvalidRect;
  moveControl->QueryBounds(reinterpret_cast<int*>(&moveBoundsRect));
  OffsetRect(&moveBoundsRect, ownerOffsetX, ownerOffsetY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
      (int)&moveInvalidRect, 1);

  TAmtBar* barControl = reinterpret_cast<TView*>(reinterpret_cast<TradeMovePanelContext*>(this))->ResolveControlByTag(kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(0xb49);
  }

  TradeMoveControlState* barLayout = reinterpret_cast<TradeMoveControlState*>(barControl);
  TAmtBar* barAmount = reinterpret_cast<TAmtBar*>(barControl);
  float barScale = 9999.0f;
  if (barLayout->barStepsRaw != 0) {
    barScale = (float)barLayout->barRangeRaw / (float)barLayout->barStepsRaw;
  }

  if (ReadControlValueFieldPlus4(selectedControl) == selectedMetricValue) {
    barAmount->auxValueB = 0x34;
  } else {
    barAmount->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedControl->QueryValue() * barScale);
  int scaledRange = (int)((float)ReadControlValueFieldPlus4(selectedControl) * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  reinterpret_cast<TUberCluster*>(reinterpret_cast<TradeMovePanelContext*>(this)->GetControlFlag(0, 0)->ownerContext);
  return 0;
}

// GHIDRA_NAME UpdateTradeBarFromSelectedMetricRatio_B
// GHIDRA_PROTO void __fastcall UpdateTradeBarFromSelectedMetricRatio_B(int * this)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Computes bar position from selected metric ratio and applies it to bar control.
// GHIDRA_COMMENT_END
/* Computes bar position from selected metric ratio and applies it to bar control. */

// FUNCTION: IMPERIALISM 0x00588f60
int TIndustryCluster::GetControlFlag(int arg1, int arg2) {
  UpdateTradeBarFromSelectedMetricRatio(reinterpret_cast<TradeMovePanelContext*>(this), kAssertLineRatioB);
  return 0;
}
