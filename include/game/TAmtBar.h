#pragma once

#include "game/TView.h"

// VTABLE: IMPERIALISM 0x00665cc8
struct TradeAmountBarLayout : public TView {
  short rangeOrMaxValue;
  short stepOrCurrentValue;
  short auxValueA;
  short auxValueB;

  TradeAmountBarLayout();
  void UpdateNationStateGaugeValuesFromScenarioRecordCode();
  void RenderPrimarySurfaceOverlayPanelWithClipCache();
};

__inline TradeAmountBarLayout::TradeAmountBarLayout()
    : rangeOrMaxValue(0), stepOrCurrentValue(0), auxValueA(0), auxValueB(0) {}

struct TradeMoveControlState {
  void* vftable;
  char pad_04[0x1c];
  void* ownerContext;
  char pad_24[0x10];
  int barRangeRaw;
  char pad_38[0x2c];
  short barStepsRaw;

  void ClampAndApplyTradeMoveValue(int* requestedValuePtr);
};
