#pragma once

#include "compat.h"
#include "game/TView.h"

// VTABLE: IMPERIALISM 0x665cc8
struct CRuntimeClass;
class TAmtBar : public TView {
public:
  short rangeOrMaxValue;    // 0x60
  short stepOrCurrentValue; // 0x62
  short auxValueA;          // 0x64
  short auxValueB;          // 0x66

  TAmtBar();
  CRuntimeClass* GetRuntimeClass() override;
  // Destructor is compiler-generated (implicit virtual dtor from TView).

  void RenderPrimarySurfaceOverlayPanelWithClipCache();
  void UpdateBarValuesAndRefresh(short valueAt60, short valueAt62);
  void InvokeSlot1A8NoArg();

  virtual int ApplyMoveClamp(int baseValue, int requestedValue);
  void ClampAndApplyTradeMoveValue(int* requestedValuePtr);
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

ASSERT_SIZE(TAmtBar, 0x68);
