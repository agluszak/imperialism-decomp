// Included by src/game/trade_screen.cpp.
// Contains trade amount-bar class wrappers (address-ordered).









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
