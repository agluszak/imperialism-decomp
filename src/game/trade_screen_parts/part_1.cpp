// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context; then initializes move/bar controls baseline.
// GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */















// FUNCTION: IMPERIALISM 0x00587130
void TradeScreenContext::InitializeTradeSellControlState(void)
{
  TradeControl *sellControl = ResolveControlByTag(kControlTagSell);
  if (sellControl != 0) {
    int styleDescriptor[5] = {0, 0, 0, 0, 0};
    int boundsBuffer[2] = {0, 0};
    sellControl->ApplyStyleDescriptor(styleDescriptor, 0);
    sellControl->SetStyleState(-1, 0);
    sellControl->QueryBounds(boundsBuffer);
    boundsBuffer[1] = boundsBuffer[1] - 2;
    sellControl->ApplyBounds(boundsBuffer, 1);
    sellControl->SetStatePair(-1, 0);
  }

  TradeControl *barControl = ResolveControlByTag(kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitBar);
  }
  barControl->SetStatePair(0, 0);

  TradeControl *leftControl = ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitLeft);
  }
  TradeControl *rightControl = ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitRight);
  }
  leftControl->SetStatePair(0, 0);
  rightControl->SetStatePair(0, 0);

  short activeNationSlot = QueryActiveNationId();
  NationState *activeNationState = GetNationStateBySlot(activeNationSlot);
  if (activeNationState != 0 && QueryNationTradeCapacity(activeNationState) == 0) {
    leftControl->SetEnabledPair(0, 0);
    rightControl->SetEnabledPair(0, 0);
    barControl->SetEnabledPair(0, 0);
    TradeControl *greenControl = RequireControlByTag(kControlTagGree);
    if (greenControl != 0) {
      greenControl->SetEnabledPair(0, 0);
    }
  }

  InitializeTradeMoveAndBarControls();
}

// GHIDRA_NAME IsTradeSellControlAtMinimum
// GHIDRA_PROTO void __cdecl IsTradeSellControlAtMinimum(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns early if UI mode is outside trade range (>3). Otherwise queries current Sell control quantity.
// GHIDRA_COMMENT_END
//
// NOTE:
// GHIDRA showed `g_pUiRuntimeContext` as a global here; this reconstruction passes it explicitly.
//















// FUNCTION: IMPERIALISM 0x00587900
void __cdecl IsTradeSellControlAtMinimum(TradeScreenContext *context, UiRuntimeContext *runtimeContext)
{
  if (QueryUiScreenMode(runtimeContext) > 3) {
    return;
  }
  TradeControl *sellControl = context->RequireControlByTag(kControlTagSell);
  if (sellControl == 0) {
    return;
  }
  sellControl->QueryValue();
}

// GHIDRA_NAME QueryTradeSellControlQuantity
// GHIDRA_PROTO void __cdecl QueryTradeSellControlQuantity(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns current Sell control quantity via child control tag "Sell" and vfunc +0x1E8.
// GHIDRA_COMMENT_END
/* Returns current Sell control quantity via child control tag "Sell" and vfunc +0x1E8. */















// FUNCTION: IMPERIALISM 0x00587950
void TradeScreenContext::QueryTradeSellControlQuantity(void)
{
  TradeControl *sellControl = RequireControlByTag(kControlTagSell);
  if (sellControl == 0) {
    return;
  }
  sellControl->QueryValue();
}

// GHIDRA_NAME IsTradeBidControlActionable
// GHIDRA_PROTO void __cdecl IsTradeBidControlActionable(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI predicate for Bid control interactivity.
// GHIDRA_COMMENT Looks up control tag 'card' and returns true when control bitmap is 2111 (0x83F) or 2125 (0x84D) and control reports actionable state via vtable+0xEC.
// GHIDRA_COMMENT_END

/* Trade UI predicate for Bid control interactivity.
   Looks up control tag 'card' and returns true when control bitmap is 2111 (0x83F) or 2125 (0x84D)
   and control reports actionable state via vtable+0xEC. */















// FUNCTION: IMPERIALISM 0x00587980
char TradeScreenContext::IsTradeBidControlActionable(void)
{
  TradeScreenVirtualShape *screen = AsTradeScreenVirtualShape(this);
  TradeControlVirtualShape *bidControl = screen->ResolveControlByTagSlot94(kControlTagCard);
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidActionable);
  }

  if (bidControl->bitmapId != kTradeBitmapBidStateA &&
      bidControl->bitmapId != kTradeBitmapBidStateB) {
    return 0;
  }

  char actionable = bidControl->IsActionableSlotEC();
  if (actionable == 0) {
    return 0;
  }
  return 1;
}

// GHIDRA_NAME IsTradeOfferControlActionable
// GHIDRA_PROTO void __cdecl IsTradeOfferControlActionable(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI predicate for Offer control interactivity.
// GHIDRA_COMMENT Looks up control tag 'offr' and returns true when control bitmap is 2113 (0x841) or 2127 (0x84F) and control reports actionable state via vtable+0xEC.
// GHIDRA_COMMENT_END

/* Trade UI predicate for Offer control interactivity.
   Looks up control tag 'offr' and returns true when control bitmap is 2113 (0x841) or 2127 (0x84F)
   and control reports actionable state via vtable+0xEC. */

















// FUNCTION: IMPERIALISM 0x00587A10
char TradeScreenContext::IsTradeOfferControlActionable(void)
{
  TradeScreenVirtualShape *screen = AsTradeScreenVirtualShape(this);
  TradeControlVirtualShape *offerControl = screen->ResolveControlByTagSlot94(kControlTagOffr);
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferActionable);
  }

  if (offerControl->bitmapId != kTradeBitmapOfferStateA &&
      offerControl->bitmapId != kTradeBitmapOfferStateB) {
    return 0;
  }

  char actionable = offerControl->IsActionableSlotEC();
  if (actionable == 0) {
    return 0;
  }
  return 1;
}


// GHIDRA_NAME SetTradeBidSecondaryBitmapState
// GHIDRA_PROTO void __cdecl SetTradeBidSecondaryBitmapState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI Bid secondary-state updater.
// GHIDRA_COMMENT Resolves 'card' control and assigns 2112 (0x840) or 2126 (0x84E) through vtable+0x1C8 based on row state field (+0x1C == 0x67643020) when nation availability gate passes.
// GHIDRA_COMMENT_END

/* Trade UI Bid secondary-state updater.
   Resolves 'card' control and assigns 2112 (0x840) or 2126 (0x84E) through vtable+0x1C8 based on
   row state field (+0x1C == 0x67643020) when nation availability gate passes. */

// NOTE:
// GHIDRA showed `g_pUiRuntimeContext` as a global here; this reconstruction passes it explicitly.
//














// FUNCTION: IMPERIALISM 0x00587AA0
void TradeScreenContext::SetTradeBidSecondaryBitmapState(void)
{
  TradeControl *bidControl = ResolveControlByTag(kControlTagCard);
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidSecondary);
  }

  int layoutCapture[2];
  layoutCapture[0] = 0x11;
  layoutCapture[1] = 0x14;
  bidControl->CaptureLayout(layoutCapture, 1);

  if (QueryUiScreenModeRaw(g_pUiRuntimeContext) < 4) {
    bidControl->SetEnabledPair(1, 1);
    if (rowStateTag == kTradeRowStateTag_67643020) {
      bidControl->SetBitmap(kTradeBitmapBidSecondaryStateB, 0);
    } else {
      bidControl->SetBitmap(kTradeBitmapBidSecondaryStateA, 0);
    }
    bidControl->Refresh();
    bidControl->UpdateAfterBitmapChange(0);
    return;
  }

  bidControl->SetEnabledPair(0, 1);
}

// GHIDRA_NAME SetTradeBidControlBitmapState
// GHIDRA_PROTO void __cdecl SetTradeBidControlBitmapState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI Bid-state updater.
// GHIDRA_COMMENT Resolves control tag 'card' from current row context.
// GHIDRA_COMMENT If row state field (+0x1C) equals 0x67643020, assigns bitmap 2125 (0x84D); otherwise assigns bitmap 2111 (0x83F).
// GHIDRA_COMMENT Then refreshes related controls 'gree', 'left', 'rght' visibility/active flags.
// GHIDRA_COMMENT_END

/* Trade UI Bid-state updater.
   Resolves control tag 'card' from current row context.
   If row state field (+0x1C) equals 0x67643020, assigns bitmap 2125 (0x84D); otherwise assigns
   bitmap 2111 (0x83F).
   Then refreshes related controls 'gree', 'left', 'rght' visibility/active flags. */















// FUNCTION: IMPERIALISM 0x00587BB0
void TradeScreenContext::SetTradeBidControlBitmapState(void)
{
  TradeControl *bidControl = ResolveControlByTag(kControlTagCard);
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidControl);
  }

  bidControl->SetEnabledPair(1, 0);
  if (rowStateTag == kTradeRowStateTag_67643020) {
    bidControl->SetBitmap(kTradeBitmapBidStateB, 0);
  } else {
    bidControl->SetBitmap(kTradeBitmapBidStateA, 0);
  }

  int layoutCapture[2] = {0x41, 0x14};
  bidControl->CaptureLayout(layoutCapture, 1);

  TradeControl *greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidGree);
  }
  TradeControl *leftControl = ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidLeft);
  }
  TradeControl *rightControl = ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidRight);
  }

  greenControl->SetEnabledPair(0, 1);
  leftControl->SetEnabledPair(0, 1);
  rightControl->SetEnabledPair(0, 1);
  greenControl->SetStatePair(0, 1);
  leftControl->SetStatePair(0, 1);
  rightControl->SetStatePair(0, 1);

  bidControl->Refresh();
  bidControl->UpdateAfterBitmapChange(0);
}

// GHIDRA_NAME SetTradeOfferControlBitmapState
// GHIDRA_PROTO void __cdecl SetTradeOfferControlBitmapState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI Offer-state updater.
// GHIDRA_COMMENT Resolves control tag 'offr' from current row context.
// GHIDRA_COMMENT If row state field (+0x1C) equals 0x67643020, assigns bitmap 2127 (0x84F); otherwise assigns bitmap 2113 (0x841).
// GHIDRA_COMMENT Then refreshes related controls 'gree', 'left', 'rght' visibility/active flags.
// GHIDRA_COMMENT_END

/* Trade UI Offer-state updater.
   Resolves control tag 'offr' from current row context.
   If row state field (+0x1C) equals 0x67643020, assigns bitmap 2127 (0x84F); otherwise assigns
   bitmap 2113 (0x841).
   Then refreshes related controls 'gree', 'left', 'rght' visibility/active flags. */















// FUNCTION: IMPERIALISM 0x00587DD0
void TradeScreenContext::SetTradeOfferControlBitmapState(void)
{
  TradeControl *offerControl = ResolveControlByTag(kControlTagOffr);
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferControl);
  }

  offerControl->SetEnabledPair(1, 0);
  if (rowStateTag == kTradeRowStateTag_67643020) {
    offerControl->SetBitmap(kTradeBitmapOfferStateB, 0);
  } else {
    offerControl->SetBitmap(kTradeBitmapOfferStateA, 0);
  }

  int layoutCaptureF4[2] = {0x41, 0x14};
  offerControl->CaptureLayout(layoutCaptureF4, 1);
  int layoutCaptureF0[2] = {0x73, 0};
  offerControl->CaptureLayoutF0(layoutCaptureF0, 1);

  TradeControl *greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferGree);
  }
  TradeControl *leftControl = ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferLeft);
  }
  TradeControl *rightControl = ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferRight);
  }

  greenControl->SetEnabledPair(1, 1);
  leftControl->SetEnabledPair(1, 1);
  rightControl->SetEnabledPair(1, 1);
  greenControl->SetStatePair(1, 1);
  leftControl->SetStatePair(1, 1);
  rightControl->SetStatePair(1, 1);

  offerControl->Refresh();
  offerControl->UpdateAfterBitmapChange(0);
}

// GHIDRA_NAME SetTradeOfferSecondaryBitmapState
// GHIDRA_PROTO void __cdecl SetTradeOfferSecondaryBitmapState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI Offer secondary-state updater.
// GHIDRA_COMMENT Resolves 'offr' control and assigns 2114 (0x842) or 2128 (0x850) through vtable+0x1C8 based on row state field (+0x1C == 0x67643020) when nation availability gate passes.
// GHIDRA_COMMENT_END

/* Trade UI Offer secondary-state updater.
   Resolves 'offr' control and assigns 2114 (0x842) or 2128 (0x850) through vtable+0x1C8 based on
   row state field (+0x1C == 0x67643020) when nation availability gate passes. */















// FUNCTION: IMPERIALISM 0x00588030
void TradeScreenContext::SetTradeOfferSecondaryBitmapState(void)
{
  TradeControl *offerControl = ResolveControlByTag(kControlTagOffr);
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryOffr);
  }

  int layoutCaptureF4[2] = {0x11, 0x14};
  offerControl->CaptureLayout(layoutCaptureF4, 1);

  short activeNationSlot = QueryActiveNationId();
  NationState *activeNationState = GetNationStateBySlot(activeNationSlot);
  short tradeMetricAvailable = QueryNationMetricBySlot(activeNationState, tradeMetricSlot);

  if (tradeMetricAvailable != 0) {
    short activeNationSlotAgain = QueryActiveNationId();
    NationState *activeNationStateAgain = GetNationStateBySlot(activeNationSlotAgain);
    if (QueryNationTradeCapacity(activeNationStateAgain) != 0) {
      offerControl->SetEnabledPair(1, 0);
      if (rowStateTag == kTradeRowStateTag_67643020) {
        offerControl->SetBitmap(kTradeBitmapOfferSecondaryStateB, 0);
      } else {
        offerControl->SetBitmap(kTradeBitmapOfferSecondaryStateA, 0);
      }
      int layoutCaptureF0[2] = {0xa3, 1};
      offerControl->CaptureLayoutF0(layoutCaptureF0, 1);
    } else {
      offerControl->SetEnabledPair(0, 1);
    }
  } else {
    offerControl->SetEnabledPair(0, 1);
  }

  TradeControl *greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryGree);
  }
  TradeControl *leftControl = ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryLeft);
  }
  TradeControl *rightControl = ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryRight);
  }

  greenControl->SetEnabledPair(0, 1);
  greenControl->SetStatePair(0, 1);
  leftControl->SetEnabledPair(0, 1);
  leftControl->SetStatePair(0, 1);
  rightControl->SetEnabledPair(0, 1);
  rightControl->SetStatePair(0, 1);

  offerControl->Refresh();
  offerControl->UpdateAfterBitmapChange(0);
}

// GHIDRA_NAME UpdateTradeSellControlAndBarFromNationMetric
// GHIDRA_PROTO void __fastcall UpdateTradeSellControlAndBarFromNationMetric(int * this)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Updates Sell control quantity
// GHIDRA_COMMENT_END
/* Updates Sell control quantity */















// FUNCTION: IMPERIALISM 0x005882F0
void TradeScreenContext::UpdateTradeSellControlAndBarFromNationMetric(int metricClampMax)
{
  short activeNationSlot = QueryActiveNationId();
  NationState *activeNationState = GetNationStateBySlot(activeNationSlot);
  int tradeMetricValue = (int)QueryNationMetricBySlot(activeNationState, tradeMetricSlot);
  if (tradeMetricValue > metricClampMax) {
    tradeMetricValue = metricClampMax;
  }

  TradeControl *sellControl = ResolveControlByTag(kControlTagSell);
  if (sellControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateSell);
  }
  if (sellControl != 0) {
    sellControl->SetControlValue(tradeMetricValue, 1);
  }

  TradeControl *barControl = ResolveControlByTag(kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateBar);
  }
  TradeControl *greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateGree);
  }

  if (barControl != 0) {
    TradeBarControlLayout *barLayout = reinterpret_cast<TradeBarControlLayout *>(barControl);
    int barRange = (int)barLayout->barRange;
    if (tradeMetricValue != 0) {
      int barSteps = (int)barLayout->barSteps;
      float barScale = 9999.0f;
      if (barSteps != 0) {
        barScale = (float)barRange / (float)barSteps;
      }
      int scaledMetricValue = (int)((float)tradeMetricValue * barScale);
      barControl->SetBarMetric(scaledMetricValue, barRange);
      return;
    }

    barControl->SetBarMetric(0, barRange);
  }

  if (greenControl != 0) {
    greenControl->SetEnabledPair(0, 1);
  }
}

// GHIDRA_NAME TAmtBar::WrapperFor_thunk_NoOpUiLifecycleHook_At00588610
// GHIDRA_PROTO undefined WrapperFor_thunk_NoOpUiLifecycleHook_At00588610()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [WrapperShape] small wrapper around thunk_NoOpUiLifecycleHook; instructions=4, call_insns=1, internal_calls=1, unique_internal=1
// GHIDRA_COMMENT_END
/* [WrapperShape] small wrapper around thunk_NoOpUiLifecycleHook; instructions=4, call_insns=1,
   internal_calls=1, unique_internal=1 */















// FUNCTION: IMPERIALISM 0x00588610
void __stdcall WrapperFor_thunk_NoOpUiLifecycleHook_At00588610(int passthroughArg)
{
  ((void(__cdecl *)(int))thunk_NoOpUiLifecycleHook)(passthroughArg);
}

// GHIDRA_NAME OrphanCallChain_C2_I15_00588630
// GHIDRA_PROTO undefined OrphanCallChain_C2_I15_00588630()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=2; instructions=15
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=2; instructions=15 */















// FUNCTION: IMPERIALISM 0x00588630
void __fastcall OrphanCallChain_C2_I15_00588630(
    TradeControl *control, int unusedEdx, short valueAt60, short valueAt62)
{
  (void)unusedEdx;
  TradeAmountBarLayout *amountBar = reinterpret_cast<TradeAmountBarLayout *>(control);
  amountBar->stepOrCurrentValue = valueAt60;
  amountBar->rangeOrMaxValue = valueAt62;
  control->InvokeSlotE4();
  control->InvokeSlot13C();
}

// GHIDRA_NAME OrphanCallChain_C1_I03_00588670
// GHIDRA_PROTO undefined OrphanCallChain_C1_I03_00588670()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=3
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=3 */















// FUNCTION: IMPERIALISM 0x00588670
void __fastcall OrphanCallChain_C1_I03_00588670(
    TradeControl *control, int unusedEdx, int unusedStackArg)
{
  (void)unusedEdx;
  (void)unusedStackArg;
  control->InvokeSlot1A8();
}

// GHIDRA_NAME TIndustryCluster::CreateTradeMoveStepControlPanel
// GHIDRA_PROTO undefined CreateTradeMoveStepControlPanel()















// FUNCTION: IMPERIALISM 0x00588950
void TradeMoveControlState::ClampAndApplyTradeMoveValue(int *requestedValuePtr)
{
  int requestedValue = *requestedValuePtr;
  int baseValue = 0;
  if (barStepsRaw < 1 ||
      (barRangeRaw / ((int)barStepsRaw << 1) <= *requestedValuePtr)) {
    baseValue = requestedValue;
  }

  TradeControl *moveControl = reinterpret_cast<TradeControl *>(this);
  int appliedValue = moveControl->ApplyMoveClamp(baseValue, (short)requestedValue);
  TradeOwnerVirtualShape *owner = AsTradeOwnerVirtualShape(ownerContext);
  if (((short)appliedValue == 0) && requestedValue != 0) {
    TradeControl *fallbackControl =
        ResolveOwnerControl(owner, kControlTagMove);
    if (fallbackControl == 0) {
      fallbackControl = ResolveOwnerControl(owner, kControlTagSell);
    }
    if (fallbackControl != 0 && fallbackControl->QueryValue() == 0) {
      appliedValue = 1;
    }
  }

  owner->ApplyMoveValueSlot1D0(appliedValue);
}

// GHIDRA_NAME OrphanCallChain_C1_I06_00588c30
// GHIDRA_PROTO undefined OrphanCallChain_C1_I06_00588c30()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=6
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=6 */















// FUNCTION: IMPERIALISM 0x00588A30
TradeMoveStepCluster *__cdecl CreateTradeMoveStepControlPanel(void)
{
  TradeMoveStepCluster *cluster = reinterpret_cast<TradeMoveStepCluster *>(
      AllocateWithFallbackHandler(0x90));
  if (cluster != 0) {
    TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
    cluster->vftable = reinterpret_cast<void *>(kVtableTIndustryCluster);
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















// FUNCTION: IMPERIALISM 0x00588AD0
void *__cdecl GetTIndustryClusterClassNamePointer(void)
{
  return reinterpret_cast<void *>(kAddrClassDescTIndustryCluster);
}

// GHIDRA_NAME ConstructTradeMoveStepControlPanel
// GHIDRA_PROTO void __cdecl ConstructTradeMoveStepControlPanel(void)















// FUNCTION: IMPERIALISM 0x00588AF0
void __fastcall ConstructTradeMoveStepControlPanel(TradeMoveStepCluster *cluster)
{
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void *>(kVtableTIndustryCluster);
  cluster->field_88 = 0;
}

// GHIDRA_NAME TIndustryCluster::DestructTIndustryClusterMaybeFree
// GHIDRA_PROTO void __cdecl DestructTIndustryClusterMaybeFree(void)















// FUNCTION: IMPERIALISM 0x00588B20
void __fastcall DestructTIndustryClusterMaybeFree(
    TradeMoveStepCluster *cluster, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)cluster);
  }
}

// GHIDRA_NAME ClampAndApplyTradeMoveValue
// GHIDRA_PROTO void __cdecl ClampAndApplyTradeMoveValue(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Clamps requested move value and applies through control vfunc +0x1A0; enforces nonzero fallback when move/sell controls are both at zero edge case.
// GHIDRA_COMMENT_END
/* Clamps requested move value and applies through control vfunc +0x1A0; enforces nonzero fallback
   when move/sell controls are both at zero edge case. */














// FUNCTION: IMPERIALISM 0x00588B70
void __fastcall SyncTradeCommoditySelectionWithActiveNationAndInitControls(
    TradeMovePanelContext *context, int unusedEdx)
{
  (void)unusedEdx;
  short tagIndex = 0;
  NationCityTradeState *cityState = GetNationCityStateBySlot(QueryActiveNationId());
  int currentSummaryTag = context->summaryTag;
  int mappedSummaryTag = GetTradeSummarySelectionTagByIndex(tagIndex);
  while (mappedSummaryTag != currentSummaryTag) {
    tagIndex = (short)(tagIndex + 1);
    mappedSummaryTag = GetTradeSummarySelectionTagByIndex(tagIndex);
  }

  TradeCommodityMetricRecord *selectedMetricRecord = 0;
  if (cityState != 0) {
    selectedMetricRecord = cityState->tradeCommodityRecordPtrs[tagIndex];
  }
  context->selectedMetricControl = reinterpret_cast<TradeControl *>(selectedMetricRecord);
  if (selectedMetricRecord != 0) {
    context->selectedMetricValue = (short)TradeScreenRuntimeBridge::GetCityBuildingProductionValueBySlot(
        cityState, selectedMetricRecord->buildingSlot);
  } else {
    context->selectedMetricValue = 0;
  }

  TradeScreenRuntimeBridge::InitializeTradeMoveAndBarControls(context);

  short selectedControlValue = 0;
  if (selectedMetricRecord != 0) {
    selectedControlValue = selectedMetricRecord->controlValue;
  }
  TradeOwnerVirtualShape *owner =
      AsTradeOwnerVirtualShape(context->ownerContext != 0 ? context->ownerContext : context);
  owner->PostMoveValueSlot1D4(selectedControlValue, 1);
}















// FUNCTION: IMPERIALISM 0x00588C30
void TradeMovePanelContext::OrphanCallChain_C1_I06_00588c30(int value)
{
  AsTradeOwnerVirtualShape(this)->PostMoveValueSlot1D4(value, 0);
}

static __inline void UpdateTradeBarFromSelectedMetricRatio(
    TradeMovePanelContext *context, int assertLine)
{
  TradeOwnerVirtualShape *owner = AsTradeOwnerVirtualShape(context);
  TradeControl *barControl =
      ResolveOwnerControl(owner, kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(assertLine);
  }

  TradeMoveControlState *barLayout = reinterpret_cast<TradeMoveControlState *>(barControl);
  if (barLayout->barStepsRaw != 0) {
    int ratioValue =
        ((int)context->selectedMetricControl->QueryStepValue() * barLayout->barRangeRaw) /
        (int)barLayout->barStepsRaw;
    barControl->SetBarMetricRatio(ratioValue);
  }
}

// GHIDRA_NAME UpdateTradeBarFromSelectedMetricRatio_B
// GHIDRA_PROTO void __fastcall UpdateTradeBarFromSelectedMetricRatio_B(int * this)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Computes bar position from selected metric ratio and applies it to bar control.
// GHIDRA_COMMENT_END
/* Computes bar position from selected metric ratio and applies it to bar control. */














// FUNCTION: IMPERIALISM 0x00588C60
void __fastcall UpdateTradeMoveControlsFromDrag(
    TradeMovePanelContext *context, int unusedEdx, int dragValue, int updateFlag)
{
  (void)unusedEdx;
  TradeControl *selectedControl = context->selectedMetricControl;
  int previousValue = 0;
  if (selectedControl != 0) {
    previousValue = selectedControl->QueryValue();
    selectedControl->SetControlValue(dragValue, 0);
  }

  if (((char)updateFlag == 0) &&
      (selectedControl != 0) &&
      (selectedControl->QueryStepValue() == (short)previousValue)) {
    return;
  }

  TradeOwnerVirtualShape *owner =
      AsTradeOwnerVirtualShape(context->ownerContext != 0 ? context->ownerContext : context);

  TradeControl *moveControl =
      ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }
  if (selectedControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }

  moveControl->SetControlValue(selectedControl->QueryStepValue(), 0);

  TradeControl *barControl =
      ResolveOwnerControl(owner, kControlTagBar);
  if (barControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }

  TradeMoveControlState *barLayout = reinterpret_cast<TradeMoveControlState *>(barControl);
  TradeAmountBarLayout *barAmount = reinterpret_cast<TradeAmountBarLayout *>(barControl);
  float barScale = 9999.0f;
  if (barLayout->barStepsRaw != 0) {
    barScale = (float)barLayout->barRangeRaw / (float)barLayout->barStepsRaw;
  }

  if (selectedControl->QueryStepValue() == context->selectedMetricValue) {
    barAmount->auxValueB = 0x34;
  } else {
    barAmount->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedControl->QueryValue() * barScale);
  int scaledRange = (int)((float)selectedControl->QueryStepValue() * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  owner->NotifyMoveUpdatedSlot1D8();
}















// FUNCTION: IMPERIALISM 0x00588F60
void TradeMovePanelContext::UpdateTradeBarFromSelectedMetricRatio_B(void)
{
  UpdateTradeBarFromSelectedMetricRatio(this, kAssertLineRatioB);
}

// GHIDRA_NAME TAmtBar::HandleTradeMoveStepCommand
// GHIDRA_PROTO void __thiscall HandleTradeMoveStepCommand(void)















// FUNCTION: IMPERIALISM 0x00588FF0
void TradeMovePanelContext::HandleTradeMoveStepCommand(int commandId)
{
  TradeOwnerVirtualShape *owner = AsTradeOwnerVirtualShape(this);
  if (commandId == 100) {
    TradeControl *moveControl =
        ResolveOwnerControl(owner, kControlTagMove);
    if (moveControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    }
    int moveValue = moveControl->QueryValue();
    owner->ApplyMoveValueSlot1D0(moveValue + 1);
    return;
  }
  if (commandId != 0x65) {
    HandleTradeMoveControlAdjustment();
    return;
  }

  TradeControl *moveControl =
      ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
  }
  int moveValue = moveControl->QueryValue();
  if (commandId == 0x65) {
    owner->ApplyMoveValueSlot1D0(moveValue - 1);
  }
}

// GHIDRA_NAME OrphanCallChain_C1_I06_005899c0
// GHIDRA_PROTO undefined OrphanCallChain_C1_I06_005899c0()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=6
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=6 */














// FUNCTION: IMPERIALISM 0x00589110
TradeAmountBarLayout *__cdecl CreateTIndustryAmtBarInstance(void)
{
  TradeAmountBarLayout *amountBar = reinterpret_cast<TradeAmountBarLayout *>(
      AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void *>(kVtableTIndustryAmtBar);
    amountBar->rangeOrMaxValue = 0;
    amountBar->stepOrCurrentValue = 0;
    amountBar->auxValueA = 0;
    amountBar->auxValueB = 0;
  }
  return amountBar;
}














// FUNCTION: IMPERIALISM 0x005891B0
void *__cdecl GetTIndustryAmtBarClassNamePointer(void)
{
  return reinterpret_cast<void *>(kAddrClassDescTIndustryAmtBar);
}














// FUNCTION: IMPERIALISM 0x005891D0
TradeAmountBarLayout *__fastcall ConstructTIndustryAmtBarBaseState(TradeAmountBarLayout *amountBar)
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
  amountBar->vftable = reinterpret_cast<void *>(kVtableTIndustryAmtBar);
  amountBar->rangeOrMaxValue = 0;
  amountBar->stepOrCurrentValue = 0;
  amountBar->auxValueA = 0;
  amountBar->auxValueB = 0;
  return amountBar;
}














// FUNCTION: IMPERIALISM 0x00589210
TradeAmountBarLayout *__fastcall DestructTIndustryAmtBarAndMaybeFree(
    TradeAmountBarLayout *amountBar, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)amountBar);
  }
  return amountBar;
}













// FUNCTION: IMPERIALISM 0x00589260
void __fastcall InitializeTradeBarsFromSelectedCommodityControl(IndustryAmtBarState *amountBar)
{
  NationCityTradeState *cityState = GetNationCityStateBySlot(QueryActiveNationId());
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
  amountBar->cachedRatioAt62 = (short)((stepValue * amountBar->barRangeRaw) / amountBar->cachedProductionAt64);

  amountBar->cachedStyleAt66 = 0x3a;
  amountBar->cachedRangeAt60 = (short)(
      (amountBar->selectedMetricRecord->controlValue * amountBar->barRangeRaw) /
      amountBar->cachedProductionAt64);

  thunk_NoOpUiLifecycleHook();
}












// FUNCTION: IMPERIALISM 0x00589660
TradeMoveStepCluster *__cdecl CreateTradeMoveScaledControlPanel(void)
{
  TradeMoveStepCluster *cluster = reinterpret_cast<TradeMoveStepCluster *>(
      AllocateWithFallbackHandler(0x90));
  if (cluster != 0) {
    TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
    cluster->vftable = reinterpret_cast<void *>(kVtableTRailCluster);
    cluster->field_88 = 0;
    cluster->field_8e = 0;
  }
  return cluster;
}














// FUNCTION: IMPERIALISM 0x00589700
void *__cdecl GetTRailClusterClassNamePointer(void)
{
  return reinterpret_cast<void *>(kAddrClassDescTRailCluster);
}














// FUNCTION: IMPERIALISM 0x00589720
void __fastcall ConstructTradeMoveScaledControlPanel(TradeMoveStepCluster *cluster)
{
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void *>(kVtableTRailCluster);
  cluster->field_88 = 0;
  cluster->field_8e = 0;
}














// FUNCTION: IMPERIALISM 0x00589760
void __fastcall DestructTRailClusterMaybeFree(
    TradeMoveStepCluster *cluster, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)cluster);
  }
}












// FUNCTION: IMPERIALISM 0x005897B0
void __fastcall SelectTradeCommodityPresetBySummaryTagAndInitControls(
    TradeMovePanelContext *context, int unusedEdx)
{
  (void)unusedEdx;
  NationCityTradeState *cityState = GetNationCityStateBySlot(QueryActiveNationId());
  CityTradeScenarioDescriptor *scenario =
      cityState != 0 ? cityState->scenarioTradeDescriptor : 0;

  short recordIndex = 0;
  context->selectedMetricStep = 0;
  context->selectedMetricValue = 0;

  if (context->summaryTag == kSummaryTagPopu) {
    recordIndex = 0x3c;
    context->selectedMetricStep = 1;
    if (cityState != 0) {
      context->selectedMetricValue = (short)TradeScreenRuntimeBridge::GetCityBuildingProductionValueBySlot(
          cityState, 0x0f);
    }
  } else if (context->summaryTag == kSummaryTagFood) {
    recordIndex = 7;
    context->selectedMetricStep = 2;
    if (scenario != 0 && scenario->productionSlots != 0) {
      CityTradeProductionSlots *slots = scenario->productionSlots;
      context->selectedMetricValue = (short)(
          ((slots->valueAt8 * 2 + slots->valueAt6) * 2 + scenario->extraAt1E + slots->valueAt4) / 2);
    }
  } else if (context->summaryTag == kSummaryTagProf) {
    recordIndex = 0x18;
    context->selectedMetricStep = 1;
    if (scenario != 0 && scenario->productionSlots != 0) {
      context->selectedMetricValue = scenario->productionSlots->valueAt6;
    }
  } else if (context->summaryTag == kSummaryTagPowe) {
    recordIndex = 0x34;
    context->selectedMetricStep = 6;
    context->selectedMetricValue = 999;
  } else if (context->summaryTag == kSummaryTagRail) {
    recordIndex = 0x33;
    context->selectedMetricStep = 1;
    if (scenario != 0 && scenario->productionSlots != 0) {
      CityTradeProductionSlots *slots = scenario->productionSlots;
      context->selectedMetricValue = (short)(
          ((slots->valueAt8 * 2 + slots->valueAt6) * 2 + slots->valueAt4 + scenario->extraAt1E) / 2);
    }
  } else if (context->summaryTag == kSummaryTagIart) {
    recordIndex = 0x17;
    context->selectedMetricStep = 1;
    if (scenario != 0 && scenario->productionSlots != 0) {
      context->selectedMetricValue = scenario->productionSlots->valueAt4;
    }
  }

  TradeCommodityMetricRecord *metricRecord = 0;
  if (cityState != 0) {
    metricRecord = cityState->tradeCommodityRecordPtrs[recordIndex];
  }
  context->selectedMetricControl = reinterpret_cast<TradeControl *>(metricRecord);

  TradeScreenRuntimeBridge::InitializeTradeMoveAndBarControls(context);

  short selectedControlValue = metricRecord != 0 ? metricRecord->controlValue : 0;
  TradeOwnerVirtualShape *owner =
      AsTradeOwnerVirtualShape(context->ownerContext != 0 ? context->ownerContext : context);
  owner->PostMoveValueSlot1D4(selectedControlValue, 1);
}















// FUNCTION: IMPERIALISM 0x005899C0
void TradeMovePanelContext::OrphanCallChain_C1_I06_005899c0(int value)
{
  AsTradeOwnerVirtualShape(this)->PostMoveValueSlot1D4(value, 0);
}

// GHIDRA_NAME UpdateTradeBarFromSelectedMetricRatio_A
// GHIDRA_PROTO void __fastcall UpdateTradeBarFromSelectedMetricRatio_A(int * this)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Computes bar position from selected metric ratio and applies it to bar control.
// GHIDRA_COMMENT_END
/* Computes bar position from selected metric ratio and applies it to bar control. */












// FUNCTION: IMPERIALISM 0x005899F0
void TradeMovePanelContext::UpdateTradeMoveControlsFromScaledDrag(int dragValue, int updateFlag)
{
  short step = selectedMetricStep;
  int quantizedDragValue = dragValue;
  if (step != 0) {
    quantizedDragValue = (((int)step / 2 + (int)(short)dragValue) / (int)step) * (int)step;
  }

  TradeControl *selectedControl = selectedMetricControl;
  int previousValue = 0;
  if (selectedControl != 0) {
    previousValue = selectedControl->QueryValue();
    selectedControl->SetControlValue(quantizedDragValue, 0);
  }

  if (((char)updateFlag == 0) &&
      (selectedControl != 0) &&
      (selectedControl->QueryStepValue() == (short)previousValue)) {
    return;
  }

  TradeOwnerVirtualShape *owner =
      AsTradeOwnerVirtualShape(ownerContext != 0 ? ownerContext : this);

  TradeControl *moveControl =
      ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }
  if (selectedControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }

  moveControl->SetControlValue(selectedControl->QueryStepValue(), 0);

  TradeControl *barControl =
      ResolveOwnerControl(owner, kControlTagBar);
  if (barControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }

  TradeMoveControlState *barLayout = reinterpret_cast<TradeMoveControlState *>(barControl);
  TradeAmountBarLayout *barAmount = reinterpret_cast<TradeAmountBarLayout *>(barControl);
  float barScale = 9999.0f;
  if (barLayout->barStepsRaw != 0) {
    barScale = (float)barLayout->barRangeRaw / (float)barLayout->barStepsRaw;
  }

  if (selectedControl->QueryStepValue() == selectedMetricValue) {
    barAmount->auxValueB = 0x34;
  } else {
    barAmount->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedControl->QueryValue() * barScale);
  int scaledRange = (int)((float)selectedControl->QueryStepValue() * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  owner->NotifyMoveUpdatedSlot1D8();
}















// FUNCTION: IMPERIALISM 0x00589D10
void TradeMovePanelContext::UpdateTradeBarFromSelectedMetricRatio_A(void)
{
  UpdateTradeBarFromSelectedMetricRatio(this, kAssertLineRatioA);
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif











// FUNCTION: IMPERIALISM 0x00589DA0
void TradeMoveStepCluster::HandleTradeMovePageStepCommand(
    int commandId, void *eventArg, int eventExtra)
{
  TradeOwnerVirtualShape *owner = AsTradeOwnerVirtualShape(this);

  int relative = commandId - 100;
  if (relative != 0) {
    if (relative == 1) {
      TradeControl *moveControl = ResolveOwnerControl(owner, kControlTagMove);
      if (moveControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineMovePageMinus);
        return;
      }
      short moveValue = (short)moveControl->QueryValue();
      owner->ApplyMoveValueSlot1D0((int)moveValue - (int)field_8e);
      return;
    }
    reinterpret_cast<void (*)(TradeMoveStepCluster *, int, void *, int)>(
        ::thunk_HandleTradeMoveControlAdjustment)(this, commandId, eventArg, eventExtra);
    return;
  }

  TradeControl *moveControl = ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineMovePagePlus);
    return;
  }
  short moveValue = (short)moveControl->QueryValue();
  owner->ApplyMoveValueSlot1D0((int)field_8e + (int)moveValue);
}











// FUNCTION: IMPERIALISM 0x00589ED0
IndustryAmtBarState *__cdecl CreateTRailAmtBarInstance(void)
{
  IndustryAmtBarState *amountBar = reinterpret_cast<IndustryAmtBarState *>(
      AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void *>(kVtableTRailAmtBar);
    amountBar->cachedRangeAt60 = 0;
    amountBar->cachedRatioAt62 = 0;
    amountBar->cachedProductionAt64 = 0;
    amountBar->cachedStyleAt66 = 0;
  }
  return amountBar;
}











// FUNCTION: IMPERIALISM 0x00589F70
void *__cdecl GetTRailAmtBarClassNamePointer(void)
{
  return reinterpret_cast<void *>(kAddrClassDescTRailAmtBar);
}











// FUNCTION: IMPERIALISM 0x00589F90
IndustryAmtBarState *IndustryAmtBarState::ConstructTRailAmtBarBaseState()
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(this);
  vftable = reinterpret_cast<void *>(kVtableTRailAmtBar);
  cachedRangeAt60 = 0;
  cachedRatioAt62 = 0;
  cachedProductionAt64 = 0;
  cachedStyleAt66 = 0;
  return this;
}











// FUNCTION: IMPERIALISM 0x00589FD0
IndustryAmtBarState *IndustryAmtBarState::DestructTRailAmtBarAndMaybeFree(unsigned char freeSelfFlag)
{
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)this);
  }
  return this;
}











// FUNCTION: IMPERIALISM 0x0058A020
void IndustryAmtBarState::SelectTradeSummaryMetricByTagAndUpdateBarValues()
{
  NationCityTradeState *cityState = GetNationCityStateBySlot(QueryActiveNationId());
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
    CityTradeScenarioDescriptor *scenario = cityState->scenarioTradeDescriptor;
    CityTradeProductionSlots *slots = scenario->productionSlots;
    productionOrCapValue = (short)(
        ((slots->valueAt8 * 2 + slots->valueAt6) * 2 + scenario->extraAt1E + slots->valueAt4) / 2);
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










// FUNCTION: IMPERIALISM 0x0058A4D0
TradeMoveStepCluster *__cdecl CreateTradeMoveArrowControlPanel(void)
{
  TradeMoveStepCluster *cluster = reinterpret_cast<TradeMoveStepCluster *>(
      AllocateWithFallbackHandler(0x90));
  if (cluster != 0) {
    TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
    cluster->vftable = reinterpret_cast<void *>(kVtableTShipyardCluster);
    cluster->field_88 = 0;
  }
  return cluster;
}










// FUNCTION: IMPERIALISM 0x0058A570
void *__cdecl GetTShipyardClusterClassNamePointer(void)
{
  return reinterpret_cast<void *>(kAddrClassDescTShipyardCluster);
}










// FUNCTION: IMPERIALISM 0x0058A590
TradeMoveStepCluster *__fastcall ConstructTradeMoveArrowControlPanel(TradeMoveStepCluster *cluster)
{
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void *>(kVtableTShipyardCluster);
  cluster->field_88 = 0;
  return cluster;
}










// FUNCTION: IMPERIALISM 0x0058A5C0
void __fastcall DestructTShipyardClusterMaybeFree(
    TradeMoveStepCluster *cluster, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)cluster);
  }
}










// FUNCTION: IMPERIALISM 0x0058A610
void TradeMoveStepCluster::SelectTradeSpecialCommodityAndInitializeControls()
{
  NationCityTradeState *cityState = GetNationCityStateBySlot(QueryActiveNationId());
  field_88 = cityState != 0 ? (int)cityState->specialCommodityRecordAt190 : 0;
  field_8c = 999;
  TradeScreenRuntimeBridge::InitializeTradeMoveAndBarControls(
      reinterpret_cast<TradeMovePanelContext *>(this));
  AsTradeOwnerVirtualShape(this)->ApplyMoveValueSlot1D0(0);
}










// FUNCTION: IMPERIALISM 0x0058A940
void TradeMoveStepCluster::HandleTradeMoveArrowControlEvent(
    int commandId, TradeControl *sourceControl, int eventExtra)
{
  if (commandId != 10) {
    reinterpret_cast<void (*)(TradeMoveStepCluster *, int, TradeControl *, int)>(
        ::thunk_HandleTradeMoveControlAdjustment)(this, commandId, sourceControl, eventExtra);
    return;
  }

  if (sourceControl != 0 && sourceControl->controlTag == kControlTagRght) {
    TradeControl *moveControl = ResolveOwnerControl(AsTradeOwnerVirtualShape(this), kControlTagMove);
    if (moveControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
      return;
    }
    AsTradeOwnerVirtualShape(this)->ApplyMoveValueSlot1D0(moveControl->QueryValue() + 1);
    return;
  }

  if (sourceControl == 0 || sourceControl->controlTag != kControlTagLeft) {
    reinterpret_cast<void (*)(TradeMoveStepCluster *, int, TradeControl *, int)>(
        ::thunk_HandleTradeMoveControlAdjustment)(this, commandId, sourceControl, eventExtra);
    return;
  }

  TradeControl *moveControl = ResolveOwnerControl(AsTradeOwnerVirtualShape(this), kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }
  int moveValue = moveControl->QueryValue();
  if ((short)moveValue != 0) {
    AsTradeOwnerVirtualShape(this)->ApplyMoveValueSlot1D0(moveValue - 1);
  }
}









