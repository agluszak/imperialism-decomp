#pragma once

#include "compat.h"
#include "game/ui_core/TView.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x665cc8
class TAmtBar : public TView {
public:
  virtual ~TAmtBar() override; // slot 0x01 (scalar deleting destructor)
  short rangeOrMaxValue;       // 0x60
  short stepOrCurrentValue;    // 0x62
  short auxValueA;             // 0x64
  short auxValueB;             // 0x66

  TAmtBar();
  DECLARE_DYNCREATE(TAmtBar)

  // TView-branch slot overrides (0xdc, 0x110, 0x11c).
  void DoPostCreate(int arg) override;
  void Draw(RECT* rectBuffer) override;
  void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;

  // TAmtBar-introduced virtuals (slots 0x1a0–0x1a8 only; tail slots are NULL in orig).
  virtual short ApplyMoveClamp(int baseValue, int requestedValue);
  virtual void UpdateBarValuesAndRefresh(short valueAt60, short valueAt62);
  virtual void RenderPrimarySurfaceOverlayPanelWithClipCache();

  void SetBarMetric(int value, int range);
  void ClampAndApplyTradeMoveValue(int requestedValue);
  void SetBarMetricRatio(int value);
  // Remaining bridge methods from the retired raw-slot facade bank: each stands in
  // for a virtual on the not-yet-reconstructed 184-slot TControl-branch vtable of the
  // real receivers (TTradeCluster/TAmtBarCluster controls). Retire each by recovering
  // the receiver class and calling the real virtual (see TAmtBar/TradeControl notes).
  void ApplyStyleDescriptor(void* descriptorBuffer, int modeFlag);
  void SetStyleState(int stateValue, int modeFlag);
  void SetControlValueSlot1E4(int value, int updateFlag);
  int QueryValue();
};

ASSERT_SIZE(TAmtBar, 0x68);
