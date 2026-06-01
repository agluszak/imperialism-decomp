// Included by src/game/trade_screen.cpp.
// Contains trade amount-bar class wrappers (address-ordered).

#pragma optimize("y", on)


// FUNCTION: IMPERIALISM 0x0058ae30
TTraderAmtBarState* __cdecl CreateTTraderAmtBarInstance(void) {
  TTraderAmtBarState* amountBar =
      reinterpret_cast<TTraderAmtBarState*>(AllocateWithFallbackHandler(0x68));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->rangeOrMaxValue = 0;
    amountBar->stepOrCurrentValue = 0;
    amountBar->auxValueA = 0;
    amountBar->auxValueB = 0;
    amountBar->vftable = reinterpret_cast<void*>(&g_vtblTTraderAmtBar);
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x0058aed0
void* __cdecl GetTTraderAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTTraderAmtBar);
}

// FUNCTION: IMPERIALISM 0x0058aef0
TTraderAmtBarState* __fastcall ConstructTTraderAmtBarBaseState(TTraderAmtBarState* amountBar) {
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
  amountBar->vftable = reinterpret_cast<void*>(&g_vtblTTraderAmtBar);
  amountBar->rangeOrMaxValue = 0;
  amountBar->stepOrCurrentValue = 0;
  amountBar->auxValueA = 0;
  amountBar->auxValueB = 0;
  return amountBar;
}

void __fastcall thunk_DestructTViewBaseState_0058AF60(TView* amountBar);

// FUNCTION: IMPERIALISM 0x0058af30
TTraderAmtBarState* __fastcall DestructTTraderAmtBarMaybeFree(TTraderAmtBarState* amountBar,
                                                              int unusedEdx,
                                                              unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructTViewBaseState_0058AF60(reinterpret_cast<TView*>(amountBar));
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)amountBar);
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x004064bf
void __fastcall thunk_DestructTViewBaseState_0058AF60(TView* amountBar) {
  amountBar->~TView();
}

namespace {

const int kScenarioRecordTags[] = {
    0x72733020, 0x72733120, 0x72733220, 0x72733320, 0x72733420, 0x72733520,
    0x72733620, 0x6d613020, 0x6d613120, 0x6d613220, 0x6d613320, 0x6d613420,
    0x6d613520, 0x67643020, 0x67643120, 0x67643220, 0x67643320,
};

} // namespace

// FUNCTION: IMPERIALISM 0x0058af80
void TTraderAmtBarState::DoPostCreate(TDocument* document) {
  TradeMoveControlState* state = reinterpret_cast<TradeMoveControlState*>(this);
  NationState* nationState =
      reinterpret_cast<NationState**>(kAddrGlobalNationStates)[g_pUiRuntimeContext->GetActiveNationId()];
  int scenarioTag = *reinterpret_cast<int*>(reinterpret_cast<char*>(state->ownerContext) + 0x1c);

  short recordIndex = 0;
  while (recordIndex < 0x11) {
    if (kScenarioRecordTags[recordIndex] == scenarioTag) {
      break;
    }
    recordIndex = (short)(recordIndex + 1);
  }

  short tradeCapacity = nationState != 0 ? nationState->tradeCapacity : 0;
  if (tradeCapacity == 0) {
    stepOrCurrentValue = 0;
  } else {
    short currentValue = CallQueryNationMetricBySlot78(nationState, recordIndex);
    stepOrCurrentValue = (short)(((int)currentValue * state->barRangeRaw) / (int)tradeCapacity);
  }

  short gaugeValue = 0;
  if (nationState != 0) {
    gaugeValue = CallQueryNationMetricBySlot7C(nationState, recordIndex);
  }
  if (tradeCapacity == 0) {
    rangeOrMaxValue = 0;
  } else {
    rangeOrMaxValue = (short)((state->barRangeRaw * (int)gaugeValue) / (int)tradeCapacity);
  }

  auxValueA = tradeCapacity;
  auxValueB = 0x37;
  reinterpret_cast<TView*>(this)->thunk_NoOpUiLifecycleHook(reinterpret_cast<int>(document));
}

// FUNCTION: IMPERIALISM 0x0058b070
short TTraderAmtBarState::AdjustForZero(short priorResult, short requestedValue) {
  short result = priorResult;
  if (requestedValue > 0) {
    NationState* nationState =
        reinterpret_cast<NationState**>(kAddrGlobalNationStates)[g_pUiRuntimeContext->GetActiveNationId()];
    short tradeCapacity = nationState->tradeCapacity;
    if (tradeCapacity != 0) {
      TradeMoveControlState* state = reinterpret_cast<TradeMoveControlState*>(this);
      if ((int)requestedValue < (state->barRangeRaw / (int)tradeCapacity)) {
        TradeControl* sellControl = ResolveOwnerControl(state->ownerContext, kControlTagSell);
        if (sellControl != 0) {
          result = 1;
        }
      }
    }
  }
  return result;
}
