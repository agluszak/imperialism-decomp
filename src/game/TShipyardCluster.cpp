// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current
// nation/resource context; then initializes move/bar controls baseline. GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */

void* __cdecl GetTShipyardClusterClassNamePointer(void);
void __fastcall DestructTShipyardClusterMaybeFree(TradeMoveStepCluster* cluster, int unusedEdx,
                                                  unsigned char freeSelfFlag);

// FUNCTION: IMPERIALISM 0x0040153c
void __cdecl thunk_DestructTShipyardClusterMaybeFree(TradeMoveStepCluster* self,
                                                     unsigned char freeSelfFlag) {
  DestructTShipyardClusterMaybeFree(self, 0, freeSelfFlag);
}

// FUNCTION: IMPERIALISM 0x00402c11
void __fastcall thunk_SelectTradeSpecialCommodityAndInitializeControls(TradeMoveStepCluster* self) {
  // ORIG_CALLCONV: __thiscall
  self->SelectTradeSpecialCommodityAndInitializeControls();
}

// FUNCTION: IMPERIALISM 0x004058a8
void __fastcall thunk_RefreshTradeMoveBarAndTurnControl(TradeMoveStepCluster* self) {
  // ORIG_CALLCONV: __thiscall
  self->RefreshTradeMoveBarAndTurnControl();
}

// FUNCTION: IMPERIALISM 0x00406965
void __fastcall thunk_HandleTradeMoveArrowControlEvent(TradeMoveStepCluster* self, int unusedEdx,
                                                       int commandId, TradeControl* sourceControl,
                                                       int eventExtra) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  self->HandleTradeMoveArrowControlEvent(commandId, sourceControl, eventExtra);
}

// FUNCTION: IMPERIALISM 0x00406e65
void* __cdecl thunk_GetTShipyardClusterClassNamePointer(void) {
  return GetTShipyardClusterClassNamePointer();
}

// FUNCTION: IMPERIALISM 0x0058a4d0
TradeMoveStepCluster* __cdecl CreateTradeMoveArrowControlPanel(void) {
  TradeMoveStepCluster* cluster =
      reinterpret_cast<TradeMoveStepCluster*>(AllocateWithFallbackHandler(0x90));
  if (cluster != 0) {
    TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
    cluster->vftable = reinterpret_cast<void*>(kVtableTShipyardCluster);
    cluster->field_88 = 0;
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x0058a570
void* __cdecl GetTShipyardClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTShipyardCluster);
}

// FUNCTION: IMPERIALISM 0x0058a590
TradeMoveStepCluster* __fastcall
ConstructTradeMoveArrowControlPanel(TradeMoveStepCluster* cluster) {
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void*>(kVtableTShipyardCluster);
  cluster->field_88 = 0;
  return cluster;
}

// FUNCTION: IMPERIALISM 0x0058a5c0
void __fastcall DestructTShipyardClusterMaybeFree(TradeMoveStepCluster* cluster, int unusedEdx,
                                                  unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)cluster);
  }
}

// FUNCTION: IMPERIALISM 0x0058a610
void TradeMoveStepCluster::SelectTradeSpecialCommodityAndInitializeControls() {
  // ORIG_CALLCONV: __thiscall
  NationCityTradeState* cityState = GetNationCityStateBySlot(QueryActiveNationId());
  field_88 = cityState != 0 ? (int)cityState->specialCommodityRecordAt190 : 0;
  field_8c = 999;
  TradeScreenRuntimeBridge::InitializeTradeMoveAndBarControls(
      reinterpret_cast<TradeMovePanelContext*>(this));
  CallApplyMoveValueSlot1D0(this, 0);
}

// FUNCTION: IMPERIALISM 0x0058a690
void TradeMoveStepCluster::RefreshTradeMoveBarAndTurnControl() {
  // ORIG_CALLCONV: __thiscall
  TradeMovePanelContext* panel = reinterpret_cast<TradeMovePanelContext*>(this);
  TradeControl* moveControl = ResolveOwnerControl(this, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    ((void(__cdecl*)(const char*, int))TemporarilyClearAndRestoreUiInvalidationFlag)(
        kUSmallViewsCppPath, 0xe5a);
  }

  moveControl->SetControlValue(0, 0);

  RECT invalidateRect;
  RECT moveRect;
  moveControl->QueryBounds(reinterpret_cast<int*>(&moveRect));
  OffsetRect(&moveRect, panel->ownerOffsetX, panel->ownerOffsetY);
  CopyRect(&invalidateRect, &moveRect);
  reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
      (int)&invalidateRect, 1);

  TradeControl* barControl = ResolveOwnerControl(this, kControlTagBar);
  if (barControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    ((void(__cdecl*)(const char*, int))TemporarilyClearAndRestoreUiInvalidationFlag)(
        kUSmallViewsCppPath, 0xe61);
  }

  TradeAmountBarLayout* barLayout = reinterpret_cast<TradeAmountBarLayout*>(barControl);
  barLayout->auxValueB = (field_8c == 0) ? 0x34 : 0x3a;
  barControl->SetBarMetric(0, 0);

  moveControl->CaptureLayoutF0(reinterpret_cast<int*>(&moveRect), 1);
  OffsetRect(&moveRect, panel->ownerOffsetX, panel->ownerOffsetY);
  CopyRect(&invalidateRect, &moveRect);
  reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
      (int)&invalidateRect, 1);

  TradeControl* turnControl = ResolveOwnerControl(panel->ownerContext, 0x7475726e);
  if (turnControl != 0) {
    turnControl->SetControlValue(0, 0);
    turnControl->QueryBounds(reinterpret_cast<int*>(&moveRect));
    CopyRect(&invalidateRect, &moveRect);
    reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
        (int)&invalidateRect, 1);
  }

  CallNotifyMoveUpdatedSlot1D8(panel->ownerContext);
}

// FUNCTION: IMPERIALISM 0x0058a940
void TradeMoveStepCluster::HandleTradeMoveArrowControlEvent(int commandId,
                                                            TradeControl* sourceControl,
                                                            int eventExtra) {
  // ORIG_CALLCONV: __thiscall
  if (commandId == 10) {
    if (sourceControl->controlTag == kControlTagRght) {
      TradeControl* moveControl = ResolveOwnerControl(this, kControlTagMove);
      if (moveControl == 0) {
        MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
      }
      int moveValue = moveControl->QueryValue();
      CallApplyMoveValueSlot1D0(this, moveValue + 1);
      return;
    }
    if (sourceControl->controlTag != kControlTagLeft) {
      HandleTradeMoveControlAdjustment(this, commandId, sourceControl, eventExtra);
      return;
    }
    TradeControl* moveControl = ResolveOwnerControl(this, kControlTagMove);
    if (moveControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    }
    int moveValue = moveControl->QueryValue();
    if ((short)moveValue != 0) {
      CallApplyMoveValueSlot1D0(this, moveValue - 1);
      return;
    }
  } else {
    HandleTradeMoveControlAdjustment(this, commandId, sourceControl, eventExtra);
  }
}
