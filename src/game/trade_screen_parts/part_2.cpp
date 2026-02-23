// Included by src/game/trade_screen.cpp.
// Contains trade amount-bar class wrappers (address-ordered).









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

