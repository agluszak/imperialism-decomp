#pragma once

#include "compat.h"
#include "game/ui_core/TView.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x665cc8
class TAmtBar : public TView {
public:
  virtual ~TAmtBar() override;
  short rangeOrMaxValue;
  short stepOrCurrentValue;
  short auxValueA;
  short auxValueB;

  // Source evidence: unreferenced retained COMDAT in retail.
  TAmtBar() : TView(), rangeOrMaxValue(0), stepOrCurrentValue(0), auxValueA(0), auxValueB(0) {}
  DECLARE_DYNCREATE(TAmtBar)

  // TView-branch slot overrides (0xdc, 0x110, 0x11c).
  void DoPostCreate(int arg) override;
  void Draw(RECT* rectBuffer) override;
  void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;

  virtual short AdjustForZero(int baseValue, short requestedValue);
  virtual void SetAmt(short valueAt60, short valueAt62);
  virtual void DrawAmt();
};

ASSERT_SIZE(TAmtBar, 0x68);
