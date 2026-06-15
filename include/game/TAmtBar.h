#pragma once

#include "compat.h"
#include "game/TView.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x665cc8
class TAmtBar : public TView {
public:
  short rangeOrMaxValue;    // 0x60
  short stepOrCurrentValue; // 0x62
  short auxValueA;          // 0x64
  short auxValueB;          // 0x66

  TAmtBar();
  CRuntimeClass* GetRuntimeClass() const override;
  // Destructor is compiler-generated (implicit virtual dtor from TView).

  // TView-branch slot overrides (0xdc, 0x110, 0x11c).
  void NoOpUiLifecycleHook(int arg) override;
  void ApplyRectSlot110(RECT* rectBuffer) override;
  void BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3, int arg4) override;

  // TAmtBar-introduced virtuals (slots 0x1a0–0x1a8 only; tail slots are NULL in orig).
  virtual int ApplyMoveClamp(int baseValue, int requestedValue);
  virtual void UpdateBarValuesAndRefresh(short valueAt60, short valueAt62);
  virtual void RenderPrimarySurfaceOverlayPanelWithClipCache();

  void SetBarMetric(int value, int range);
  void ClampAndApplyTradeMoveValue(int* requestedValuePtr);
  void InvokeSlot1A8();
  void SetBarMetricRatio(int value);
  void vmethod_0108();
  void ApplyStyleDescriptor(void* descriptorBuffer, int modeFlag);
  void vmethod_0110();
  void vmethod_0111();
  void vmethod_0112();
  void SetStyleState(int stateValue, int modeFlag);
  void SetBitmap(int bitmapIdValue, int unknownFlag);
  void InvokeSlot1CC(int value, int modeFlag);
  void vmethod_0116();
  void vmethod_0117();
  void vmethod_0118();
  void vmethod_0119();
  void vmethod_0120();
  void SetControlValueSlot1E4(int value, int updateFlag);
  int QueryValue();
};

ASSERT_SIZE(TAmtBar, 0x68);
