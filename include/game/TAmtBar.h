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
  void OrphanCallChain_C2_I15_00588630(short valueAt60, short valueAt62);
  void OrphanCallChain_C1_I03_00588670();
  void ClampAndApplyTradeMoveValue(int* requestedMovePtr);
  void SyncTradeCommoditySelectionWithActiveNationAndInitControls();
  void ApplyMoveValueSlot1D4NoCommit(int value);
  void UpdateTradeMoveControlsFromDrag(int arg1, int arg2);
  void UpdateTradeBarFromSelectedMetricRatio_B();
  void HandleTradeArrowAutoRepeatTickAndDispatch(int repeatState, void* arg8, void* argC,
                                                 void* dispatchArg, void* arg14);

  virtual int ApplyMoveClamp(int baseValue, int requestedValue);
  virtual void SetBarMetric(int value, int range);
  virtual void InvokeSlot1A8();
  virtual void SetBarMetricRatio(int value);
  virtual void vmethod_0108();
  virtual void ApplyStyleDescriptor(void* descriptorBuffer, int modeFlag);
  virtual void vmethod_0110();
  virtual void vmethod_0111();
  virtual void vmethod_0112();
  virtual void SetStyleState(int stateValue, int modeFlag);
  virtual void SetBitmap(int bitmapIdValue, int unknownFlag);
  virtual void InvokeSlot1CC(int value, int modeFlag);
  virtual void vmethod_0116();
  virtual void vmethod_0117();
  virtual void vmethod_0118();
  virtual void vmethod_0119();
  virtual void vmethod_0120();
  virtual void SetControlValueSlot1E4(int value, int updateFlag);
  virtual int QueryValue();
};
