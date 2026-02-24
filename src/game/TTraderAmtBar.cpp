// Included by src/game/trade_screen.cpp.
// Contains trade amount-bar class wrappers (address-ordered).

// FUNCTION: IMPERIALISM 0x0058AE30
TradeAmountBarLayout* __cdecl CreateTTraderAmtBarInstance(void) {
  TradeAmountBarLayout* amountBar =
      reinterpret_cast<TradeAmountBarLayout*>(AllocateWithFallbackHandler(0x68));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void*>(&g_vtblTTraderAmtBar);
    amountBar->rangeOrMaxValue = 0;
    amountBar->stepOrCurrentValue = 0;
    amountBar->auxValueA = 0;
    amountBar->auxValueB = 0;
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x0058AED0
void* __cdecl GetTTraderAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTTraderAmtBar);
}

// FUNCTION: IMPERIALISM 0x0058AEF0
TradeAmountBarLayout* __fastcall
ConstructTTraderAmtBar_Vtbl00666ba0(TradeAmountBarLayout* amountBar) {
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
  amountBar->vftable = reinterpret_cast<void*>(&g_vtblTTraderAmtBar);
  amountBar->rangeOrMaxValue = 0;
  amountBar->stepOrCurrentValue = 0;
  amountBar->auxValueA = 0;
  amountBar->auxValueB = 0;
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x0058AF30
void __fastcall DestructTTraderAmtBarMaybeFree(TradeAmountBarLayout* amountBar, int unusedEdx,
                                               unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)amountBar);
  }
}

namespace {

const int kScenarioRecordTags[] = {
    0x72733020, 0x72733120, 0x72733220, 0x72733320, 0x72733420, 0x72733520,
    0x72733620, 0x6d613020, 0x6d613120, 0x6d613220, 0x6d613320, 0x6d613420,
    0x6d613520, 0x67643020, 0x67643120, 0x67643220, 0x67643320,
};

} // namespace

// FUNCTION: IMPERIALISM 0x0058AF80
void TradeAmountBarLayout::UpdateNationStateGaugeValuesFromScenarioRecordCode() {
  TradeMoveControlState* state = reinterpret_cast<TradeMoveControlState*>(this);
  int scenarioTag = *reinterpret_cast<int*>(reinterpret_cast<char*>(state->ownerContext) + 0x1c);

  int recordIndex = 0;
  while (recordIndex < 0x11) {
    if (kScenarioRecordTags[recordIndex] == scenarioTag) {
      break;
    }
    recordIndex++;
  }

  NationState* nationState = GetNationStateBySlot(QueryActiveNationId());
  short tradeCapacity = nationState != 0 ? nationState->tradeCapacity : 0;
  if (tradeCapacity == 0) {
    stepOrCurrentValue = 0;
  } else {
    short currentValue = CallQueryNationMetricBySlot78(nationState, (short)recordIndex);
    stepOrCurrentValue = (short)(((int)currentValue * state->barRangeRaw) / (int)tradeCapacity);
  }

  short gaugeValue = 0;
  if (nationState != 0) {
    gaugeValue = CallQueryNationMetricBySlot7C(nationState, (short)recordIndex);
  }
  if (tradeCapacity == 0) {
    rangeOrMaxValue = 0;
  } else {
    rangeOrMaxValue = (short)((state->barRangeRaw * (int)gaugeValue) / (int)tradeCapacity);
  }

  auxValueA = tradeCapacity;
  auxValueB = 0x37;
  thunk_NoOpUiLifecycleHook();
}

// FUNCTION: IMPERIALISM 0x0058B070
void __fastcall WrapperFor_GetActiveNationId_At0058b070(TradeAmountBarLayout* amountBar,
                                                        int unusedEdx, short requestedValue) {
  (void)unusedEdx;
  if (requestedValue <= 0) {
    return;
  }

  NationState* nationState = GetNationStateBySlot(QueryActiveNationId());
  short tradeCapacity = nationState != 0 ? nationState->tradeCapacity : 0;
  if (tradeCapacity == 0) {
    return;
  }

  TradeMoveControlState* state = reinterpret_cast<TradeMoveControlState*>(amountBar);
  if ((int)requestedValue < (state->barRangeRaw / (int)tradeCapacity)) {
    ResolveOwnerControl(state->ownerContext, kControlTagSell);
  }
}
