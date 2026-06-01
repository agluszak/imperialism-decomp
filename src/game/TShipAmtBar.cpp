// Included by src/game/trade_screen.cpp.
// Contains trade amount-bar class wrappers (address-ordered).

#pragma optimize("y", on)



// FUNCTION: IMPERIALISM 0x0058aaa0
TShipAmtBarState* __cdecl CreateTShipAmtBarInstance(void) {
  TShipAmtBarState* amountBar =
      reinterpret_cast<TShipAmtBarState*>(AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->cachedRangeAt60 = 0;
    amountBar->cachedRatioAt62 = 0;
    amountBar->cachedProductionAt64 = 0;
    amountBar->cachedStyleAt66 = 0;
    *reinterpret_cast<void***>(amountBar) = reinterpret_cast<void**>(&g_vtblTShipAmtBar);
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x0058ab40
void* __cdecl GetTShipAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTShipAmtBar);
}

// FUNCTION: IMPERIALISM 0x0058ab60
TShipAmtBarState* TShipAmtBarState::ConstructTShipAmtBarBaseState() {
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(this);
  *reinterpret_cast<void***>(this) = reinterpret_cast<void**>(&g_vtblTShipAmtBar);
  cachedRangeAt60 = 0;
  cachedRatioAt62 = 0;
  cachedProductionAt64 = 0;
  cachedStyleAt66 = 0;
  return this;
}

void __fastcall thunk_DestructTViewBaseState_0058ABD0(TView* amountBar);

// FUNCTION: IMPERIALISM 0x004041e7
void __fastcall thunk_DestructTViewBaseState_0058ABD0(TView* amountBar) {
  amountBar->~TView();
}

// FUNCTION: IMPERIALISM 0x0058aba0
TShipAmtBarState* TShipAmtBarState::DestructTShipAmtBarAndMaybeFree(unsigned char freeSelfFlag) {
  thunk_DestructTViewBaseState_0058ABD0(this);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)this);
  }
  return this;
}

// FUNCTION: IMPERIALISM 0x0058abf0
void TShipAmtBarState::DoPostCreate(TDocument* document) {
  NationState* nationState =
      reinterpret_cast<NationState**>(kAddrGlobalNationStates)[g_pUiRuntimeContext->GetActiveNationId()];
  NationCityTradeState* cityState = nationState != 0 ? nationState->cityState : 0;
  selectedMetricRecord = cityState->specialCommodityRecordAt190;
  short productionCap =
      *(short*)(reinterpret_cast<char*>(cityState->scenarioTradeDescriptor) + 0x1c);
  cachedRatioAt62 = (short)barRangeRaw();
  cachedProductionAt64 = productionCap;
  cachedStyleAt66 = 0x3a;
  cachedRangeAt60 = (short)(0 / (int)productionCap);
  this->thunk_NoOpUiLifecycleHook(reinterpret_cast<int>(document));
}
