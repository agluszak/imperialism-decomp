// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context; then initializes move/bar controls baseline.
// GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */











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
  CallApplyMoveValueSlot1D0(this, 0);
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
    TradeControl *moveControl = ResolveOwnerControl(this, kControlTagMove);
    if (moveControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
      return;
    }
    CallApplyMoveValueSlot1D0(this, moveControl->QueryValue() + 1);
    return;
  }

  if (sourceControl == 0 || sourceControl->controlTag != kControlTagLeft) {
    reinterpret_cast<void (*)(TradeMoveStepCluster *, int, TradeControl *, int)>(
        ::thunk_HandleTradeMoveControlAdjustment)(this, commandId, sourceControl, eventExtra);
    return;
  }

  TradeControl *moveControl = ResolveOwnerControl(this, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }
  int moveValue = moveControl->QueryValue();
  if ((short)moveValue != 0) {
    CallApplyMoveValueSlot1D0(this, moveValue - 1);
  }
}
