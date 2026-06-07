#pragma once

#include "game/TView.h"

// VTABLE: IMPERIALISM 0x665cc8
class TAmtBar : public TView {
public:
  short rangeOrMaxValue;
  short stepOrCurrentValue;
  short auxValueA;
  short auxValueB;

  TAmtBar();
  virtual ~TAmtBar();

  void RenderPrimarySurfaceOverlayPanelWithClipCache();
  void ClampAndApplyTradeMoveValue(int* requestedMovePtr);
  void SyncTradeCommoditySelectionWithActiveNationAndInitControls();
  void ApplyMoveValueSlot1D4NoCommit(int value);
  void UpdateTradeMoveControlsFromDrag(int arg1, int arg2);
  void UpdateTradeBarFromSelectedMetricRatio_B();
  void HandleTradeMoveStepCommand(int commandId, void* eventArg, int eventExtra);
};
