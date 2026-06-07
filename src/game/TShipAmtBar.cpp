// Included by src/game/trade_screen.cpp.
// Contains trade amount-bar class wrappers (address-ordered).

#pragma optimize("y", on)



#include "game/TShipAmtBar.h"
#include "game/TradeControl.h"
#include "game/UiRuntimeContext.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"
#include <new>

// FUNCTION: IMPERIALISM 0x0058aaa0
TShipAmtBar* __cdecl CreateTShipAmtBarInstance(void) {
  TShipAmtBar* amountBar =
      reinterpret_cast<TShipAmtBar*>(AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    new (amountBar) TShipAmtBar;
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x0058ab40
void* __cdecl GetTShipAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTShipAmtBar);
}

// FUNCTION: IMPERIALISM 0x0058ab60
TShipAmtBar::TShipAmtBar() : TIndustryAmtBar() {
}

// FUNCTION: IMPERIALISM 0x0058aba0
TShipAmtBar::~TShipAmtBar() {
}

// FUNCTION: IMPERIALISM 0x0058abf0
void TShipAmtBar::DoPostCreate(TDocument* document) {
  NationState* nationState =
      reinterpret_cast<NationState**>(kAddrGlobalNationStates)[g_pUiRuntimeContext->GetActiveNationId()];
  NationCityTradeState* cityState = nationState != 0 ? reinterpret_cast<NationCityTradeState*>(nationState->cityState) : 0;
  selectedMetricRecord = cityState->specialCommodityRecordAt190;
  short productionCap =
      *(short*)(reinterpret_cast<char*>(cityState->scenarioTradeDescriptor) + 0x1c);
  stepOrCurrentValue = (short)barRangeRaw();
  auxValueA = productionCap;
  auxValueB = 0x3a;
  rangeOrMaxValue = (short)(0 / (int)productionCap);
  this->thunk_NoOpUiLifecycleHook(reinterpret_cast<int>(document));
}
void TShipAmtBarState::DrawAmt() {
  QuickDrawSurfaceGuard surface;
  TradeControl* control = reinterpret_cast<TradeControl*>(this);
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int boundsRect[4] = {0, 0, 0, 0};
      control->QueryBounds(boundsRect);
      ApplyRectClipRegion(boundsRect);
      control->QueryBounds(boundsRect);
      control->CtrlSlot78();

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        short styleValueAt66 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x66);
        SetQuickDrawTextOrigin(0, 1);
        ApplyQuickDrawStyleFromRuntime(styleValueAt66);
      reinterpret_cast<void*>(*reinterpret_cast<int*>(strategicMapViewSystem + 0x66c) + 4),
      reinterpret_cast<void*>(activeQuickDrawSurfaceContext + 4), &srcRect, &dstRect, 0x24, 0);

  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
}

