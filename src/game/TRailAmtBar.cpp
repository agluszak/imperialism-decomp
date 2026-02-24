// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current
// nation/resource context; then initializes move/bar controls baseline. GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */

// FUNCTION: IMPERIALISM 0x00589ed0
IndustryAmtBarState* __cdecl CreateTRailAmtBarInstance(void) {
  IndustryAmtBarState* amountBar =
      reinterpret_cast<IndustryAmtBarState*>(AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void*>(kVtableTRailAmtBar);
    amountBar->cachedRangeAt60 = 0;
    amountBar->cachedRatioAt62 = 0;
    amountBar->cachedProductionAt64 = 0;
    amountBar->cachedStyleAt66 = 0;
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x00589f70
void* __cdecl GetTRailAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTRailAmtBar);
}

// FUNCTION: IMPERIALISM 0x00589f90
IndustryAmtBarState* IndustryAmtBarState::ConstructTRailAmtBarBaseState() {
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(this);
  vftable = reinterpret_cast<void*>(kVtableTRailAmtBar);
  cachedRangeAt60 = 0;
  cachedRatioAt62 = 0;
  cachedProductionAt64 = 0;
  cachedStyleAt66 = 0;
  return this;
}

// FUNCTION: IMPERIALISM 0x00589fd0
IndustryAmtBarState*
IndustryAmtBarState::DestructTRailAmtBarAndMaybeFree(unsigned char freeSelfFlag) {
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)this);
  }
  return this;
}

// FUNCTION: IMPERIALISM 0x0058a020
void IndustryAmtBarState::SelectTradeSummaryMetricByTagAndUpdateBarValues() {
  NationCityTradeState* cityState = GetNationCityStateBySlot(QueryActiveNationId());
  int summaryTag = ownerPanelContext->summaryTag;

  short recordIndex = 0;
  if ((unsigned int)summaryTag < 0x706f7076) {
    if (summaryTag == kSummaryTagPopu) {
      recordIndex = 0x3c;
    } else if (summaryTag == kSummaryTagFood) {
      recordIndex = 7;
    }
  } else if ((unsigned int)summaryTag < 0x70726f67) {
    if (summaryTag == kSummaryTagProf) {
      recordIndex = 0x18;
    } else if (summaryTag == kSummaryTagPowe) {
      recordIndex = 0x34;
    }
  } else if (summaryTag == kSummaryTagRail) {
    recordIndex = 0x33;
  } else if (summaryTag == kSummaryTagIart) {
    recordIndex = 0x17;
  }

  selectedMetricRecord = cityState->tradeCommodityRecordPtrs[recordIndex];

  short productionOrCapValue = 0;
  if (recordIndex == 0x33 || recordIndex == 7) {
    CityTradeScenarioDescriptor* scenario = cityState->scenarioTradeDescriptor;
    CityTradeProductionSlots* slots = scenario->productionSlots;
    productionOrCapValue = (short)(((slots->valueAt8 * 2 + slots->valueAt6) * 2 +
                                    scenario->extraAt1E + slots->valueAt4) /
                                   2);
  } else {
    productionOrCapValue = selectedMetricRecord->QueryStepValue();
  }

  if (productionOrCapValue == 0) {
    cachedRatioAt62 = 9999;
  } else {
    short selectedStep = selectedMetricRecord->QueryStepValue();
    cachedRatioAt62 = (short)(((int)selectedStep * barRangeRaw) / (int)productionOrCapValue);
  }
  cachedProductionAt64 = productionOrCapValue;
  if (productionOrCapValue == 0) {
    cachedRangeAt60 = 9999;
  } else {
    cachedRangeAt60 = (short)((barRangeRaw * (int)selectedMetricRecord->controlValue) /
                              (int)productionOrCapValue);
  }
  cachedStyleAt66 = 0x3a;
  thunk_NoOpUiLifecycleHook();
}
