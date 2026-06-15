#pragma once

#include "game/TAmtBar.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666ba0
class TTraderAmtBar : public TAmtBar {
public:
  TTraderAmtBar();
  // ~TTraderAmtBar is compiler-generated (implicit virtual dtor).
  CRuntimeClass* GetRuntimeClass() override;

  void DoPostCreate(struct TDocument* document);
  short AdjustForZero(short priorResult, short requestedValue);
  void DrawAmt();
  void UpdateFromScaleOrRatio(int scaleValue, int ratioValue);
};
