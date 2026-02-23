// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context; then initializes move/bar controls baseline.
// GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */













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

