#pragma once

#include "game/TAmtBar.h"

// VTABLE: IMPERIALISM 0x666ba0
struct CRuntimeClass;
class TTraderAmtBar : public TAmtBar {
public:
  TTraderAmtBar();
  virtual ~TTraderAmtBar() override;
  CRuntimeClass* GetRuntimeClass() override;

  void DoPostCreate(struct TDocument* document);
  short AdjustForZero(short priorResult, short requestedValue);
  void DrawAmt();
  void UpdateFromScaleOrRatio(int scaleValue, int ratioValue);
};
