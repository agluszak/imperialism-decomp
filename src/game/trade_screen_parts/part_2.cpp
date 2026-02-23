// Included by src/game/trade_screen.cpp.
// Contains trade amount-bar class wrappers (address-ordered).

// FUNCTION: IMPERIALISM 0x0058AAA0
IndustryAmtBarState *__cdecl CreateTShipAmtBarInstance(void)
{
  IndustryAmtBarState *amountBar = reinterpret_cast<IndustryAmtBarState *>(
      AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void *>(&g_vtblTShipAmtBar);
    amountBar->cachedRangeAt60 = 0;
    amountBar->cachedRatioAt62 = 0;
    amountBar->cachedProductionAt64 = 0;
    amountBar->cachedStyleAt66 = 0;
  }
  return amountBar;
}









// FUNCTION: IMPERIALISM 0x0058AB40
void *__cdecl GetTShipAmtBarClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTShipAmtBar);
}









// FUNCTION: IMPERIALISM 0x0058AB60
IndustryAmtBarState *IndustryAmtBarState::ConstructTShipAmtBarBaseState()
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(this);
  vftable = reinterpret_cast<void *>(&g_vtblTShipAmtBar);
  cachedRangeAt60 = 0;
  cachedRatioAt62 = 0;
  cachedProductionAt64 = 0;
  cachedStyleAt66 = 0;
  return this;
}









// FUNCTION: IMPERIALISM 0x0058ABA0
IndustryAmtBarState *
IndustryAmtBarState::DestructTShipAmtBarAndMaybeFree(unsigned char freeSelfFlag)
{
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)this);
  }
  return this;
}









// FUNCTION: IMPERIALISM 0x0058ABF0
void IndustryAmtBarState::SelectTradeSpecialCommodityAndRecomputeBarLimits(int passthroughArg)
{
  NationState *nationState =
      reinterpret_cast<NationState **>(kAddrGlobalNationStates)[QueryActiveNationId()];
  NationCityTradeState *cityState = nationState != 0 ? nationState->cityState : 0;
  selectedMetricRecord = cityState->specialCommodityRecordAt190;
  short productionCap =
      *(short *)(reinterpret_cast<char *>(cityState->scenarioTradeDescriptor) + 0x1c);
  cachedRatioAt62 = (short)barRangeRaw;
  cachedProductionAt64 = productionCap;
  cachedStyleAt66 = 0x3a;
  cachedRangeAt60 = (short)(0 / (int)productionCap);
  reinterpret_cast<void (__fastcall *)(IndustryAmtBarState *, int)>(::thunk_NoOpUiLifecycleHook)(
      this, passthroughArg);
}








// FUNCTION: IMPERIALISM 0x0058AE30
TradeAmountBarLayout *__cdecl CreateTTraderAmtBarInstance(void)
{
  TradeAmountBarLayout *amountBar = reinterpret_cast<TradeAmountBarLayout *>(
      AllocateWithFallbackHandler(0x68));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void *>(&g_vtblTTraderAmtBar);
    amountBar->rangeOrMaxValue = 0;
    amountBar->stepOrCurrentValue = 0;
    amountBar->auxValueA = 0;
    amountBar->auxValueB = 0;
  }
  return amountBar;
}








// FUNCTION: IMPERIALISM 0x0058AED0
void *__cdecl GetTTraderAmtBarClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTTraderAmtBar);
}








// FUNCTION: IMPERIALISM 0x0058AEF0
TradeAmountBarLayout *__fastcall ConstructTTraderAmtBar_Vtbl00666ba0(TradeAmountBarLayout *amountBar)
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
  amountBar->vftable = reinterpret_cast<void *>(&g_vtblTTraderAmtBar);
  amountBar->rangeOrMaxValue = 0;
  amountBar->stepOrCurrentValue = 0;
  amountBar->auxValueA = 0;
  amountBar->auxValueB = 0;
  return amountBar;
}








// FUNCTION: IMPERIALISM 0x0058AF30
void __fastcall DestructTTraderAmtBarMaybeFree(
    TradeAmountBarLayout *amountBar, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)amountBar);
  }
}







