// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current
// nation/resource context; then initializes move/bar controls baseline. GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */

// FUNCTION: IMPERIALISM 0x00589110
TradeAmountBarLayout* __cdecl CreateTIndustryAmtBarInstance(void) {
  TradeAmountBarLayout* amountBar =
      reinterpret_cast<TradeAmountBarLayout*>(AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void*>(kVtableTIndustryAmtBar);
    amountBar->rangeOrMaxValue = 0;
    amountBar->stepOrCurrentValue = 0;
    amountBar->auxValueA = 0;
    amountBar->auxValueB = 0;
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x005891b0
void* __cdecl GetTIndustryAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTIndustryAmtBar);
}

// FUNCTION: IMPERIALISM 0x005891d0
TradeAmountBarLayout* __fastcall
ConstructTIndustryAmtBarBaseState(TradeAmountBarLayout* amountBar) {
  // ORIG_CALLCONV: __thiscall
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
  amountBar->vftable = reinterpret_cast<void*>(kVtableTIndustryAmtBar);
  amountBar->rangeOrMaxValue = 0;
  amountBar->stepOrCurrentValue = 0;
  amountBar->auxValueA = 0;
  amountBar->auxValueB = 0;
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x00589210
TradeAmountBarLayout* __fastcall
DestructTIndustryAmtBarAndMaybeFree(TradeAmountBarLayout* amountBar, int unusedEdx,
                                    unsigned char freeSelfFlag) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)amountBar);
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x00589260
void __fastcall InitializeTradeBarsFromSelectedCommodityControl(IndustryAmtBarState* amountBar) {
  // ORIG_CALLCONV: __thiscall
  NationCityTradeState* cityState = GetNationCityStateBySlot(QueryActiveNationId());
  short summaryTagIndex = 0;
  int mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  while (mappedTag != amountBar->ownerPanelContext->summaryTag) {
    summaryTagIndex = (short)(summaryTagIndex + 1);
    mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  }

  amountBar->selectedMetricRecord = cityState->tradeCommodityRecordPtrs[summaryTagIndex];
  int productionValue = TradeScreenRuntimeBridge::GetCityBuildingProductionValueBySlot(
      cityState, amountBar->selectedMetricRecord->buildingSlot);
  amountBar->cachedProductionAt64 = (short)productionValue;

  short stepValue = amountBar->selectedMetricRecord->QueryStepValue();
  amountBar->cachedRatioAt62 =
      (short)((stepValue * amountBar->barRangeRaw) / amountBar->cachedProductionAt64);

  amountBar->cachedStyleAt66 = 0x3a;
  amountBar->cachedRangeAt60 =
      (short)((amountBar->selectedMetricRecord->controlValue * amountBar->barRangeRaw) /
              amountBar->cachedProductionAt64);

  thunk_NoOpUiLifecycleHook();
}

// FUNCTION: IMPERIALISM 0x00589da0
void TradeMoveStepCluster::HandleTradeMovePageStepCommand(int commandId, void* eventArg,
                                                          int eventExtra) {
  // ORIG_CALLCONV: __thiscall
  void* owner = this;
  if (commandId == 100) {
    TradeControl* moveControl = ResolveOwnerControl(owner, kControlTagMove);
    if (moveControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    }
    short moveValue = (short)moveControl->QueryValue();
    CallApplyMoveValueSlot1D0(owner, (int)field_8e + (int)moveValue);
    return;
  }
  if (commandId != 0x65) {
    HandleTradeMoveControlAdjustment(this, commandId, eventArg, eventExtra);
    return;
  }
  TradeControl* moveControl = ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
  }
  short moveValue = (short)moveControl->QueryValue();
  CallApplyMoveValueSlot1D0(owner, (int)moveValue - (int)field_8e);
}
