#pragma once

#include "game/TAmtBar.h"
#include "game/TradeCommodityMetricRecord.h"

// VTABLE: IMPERIALISM 0x666110
class TIndustryAmtBar : public TAmtBar {
public:
  TradeCommodityMetricRecord* selectedMetricRecord;

  TIndustryAmtBar();
  virtual ~TIndustryAmtBar();

  void DoPostCreate(struct TDocument* document);
  void DrawAmt();
};
