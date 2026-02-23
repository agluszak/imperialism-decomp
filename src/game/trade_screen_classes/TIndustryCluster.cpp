// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context; then initializes move/bar controls baseline.
// GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */
















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

