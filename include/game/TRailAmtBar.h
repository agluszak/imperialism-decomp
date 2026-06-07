#pragma once

#include "game/TIndustryAmtBar.h"

// VTABLE: IMPERIALISM 0x666558
class TRailAmtBar : public TIndustryAmtBar {
public:
  TRailAmtBar();
  virtual ~TRailAmtBar();

  void DoPostCreate(struct TDocument* document);
  void DrawAmt();
};
