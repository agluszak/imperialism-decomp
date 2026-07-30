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

  // FUNCTION: IMPERIALISM 0x00588580
  TAmtBar() : TView(), rangeOrMaxValue(0), stepOrCurrentValue(0), auxValueA(0), auxValueB(0) {}
  DECLARE_DYNCREATE(TAmtBar)

  // TView-branch slot overrides (0xdc, 0x110, 0x11c).
  void DoPostCreate(int arg) override;
  void Draw(RECT* rectBuffer) override;
  void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;

  // TAmtBar-introduced virtuals (slots 0x1a0–0x1a8 only; tail slots are NULL in orig).
  // ApplyMoveClamp's second argument is a short: the base (0x00586e50) reads it with
  // MOV AX,word ptr [ESP+4] and the TTraderAmtBar override (0x0058b070) with
  // MOV DI,word ptr [ESP+0x14].
  virtual short ApplyMoveClamp(int baseValue, short requestedValue);
  virtual void UpdateBarValuesAndRefresh(short valueAt60, short valueAt62);
  virtual void RenderPrimarySurfaceOverlayPanelWithClipCache();

  void SetBarMetric(int value, int range);
};

ASSERT_SIZE(TAmtBar, 0x68);
