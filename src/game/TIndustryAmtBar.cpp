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
TIndustryAmtBarState* __cdecl CreateTIndustryAmtBarInstance(void) {
  TIndustryAmtBarState* amountBar =
      reinterpret_cast<TIndustryAmtBarState*>(AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    *reinterpret_cast<void***>(amountBar) = reinterpret_cast<void**>(kVtableTIndustryAmtBar);
    amountBar->cachedRangeAt60 = 0;
    amountBar->cachedRatioAt62 = 0;
    amountBar->cachedProductionAt64 = 0;
    amountBar->cachedStyleAt66 = 0;
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x005891b0
void* __cdecl GetTIndustryAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTIndustryAmtBar);
}

// FUNCTION: IMPERIALISM 0x005891d0
TIndustryAmtBarState* __fastcall
ConstructTIndustryAmtBarBaseState(TIndustryAmtBarState* amountBar) {
  // ORIG_CALLCONV: __thiscall
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
  *reinterpret_cast<void***>(amountBar) = reinterpret_cast<void**>(kVtableTIndustryAmtBar);
  amountBar->cachedRangeAt60 = 0;
  amountBar->cachedRatioAt62 = 0;
  amountBar->cachedProductionAt64 = 0;
  amountBar->cachedStyleAt66 = 0;
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x00589210
TIndustryAmtBarState* __fastcall
DestructTIndustryAmtBarAndMaybeFree(TIndustryAmtBarState* amountBar, int unusedEdx,
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
void TIndustryAmtBarState::DoPostCreate(TDocument* document) {
  // ORIG_CALLCONV: __thiscall
  NationState* nationState =
      reinterpret_cast<NationState**>(kAddrGlobalNationStates)[g_pUiRuntimeContext->GetActiveNationId()];
  NationCityTradeState* cityState = nationState != 0 ? nationState->cityState : 0;
  short summaryTagIndex = 0;
  int mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  while (mappedTag != ownerPanelContext()->summaryTag) {
    summaryTagIndex = (short)(summaryTagIndex + 1);
    mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  }

  selectedMetricRecord = cityState->tradeCommodityRecordPtrs[summaryTagIndex];
  int productionValue = TradeScreenRuntimeBridge::GetCityBuildingProductionValueBySlot(
      cityState, selectedMetricRecord->buildingSlot);

  short stepValue = selectedMetricRecord->QueryStepValue();
  short productionCap = (short)productionValue;
  int rangeRaw = barRangeRaw();
  cachedRatioAt62 = (short)((stepValue * rangeRaw) / productionCap);

  cachedProductionAt64 = productionCap;
  cachedStyleAt66 = 0x3a;
  cachedRangeAt60 = (short)((selectedMetricRecord->controlValue * rangeRaw) / productionCap);

  this->thunk_NoOpUiLifecycleHook(reinterpret_cast<int>(document));
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
