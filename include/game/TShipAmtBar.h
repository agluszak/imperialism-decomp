#pragma once

#include "game/TIndustryAmtBar.h"

// VTABLE: IMPERIALISM 0x666998
class TShipAmtBar : public TIndustryAmtBar {
public:
  TShipAmtBar();
  virtual ~TShipAmtBar();

  void DoPostCreate(struct TDocument* document);
  void DrawAmt();
};
