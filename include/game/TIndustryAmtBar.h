#pragma once

#include "game/TAmtBar.h"
struct TradeCommodityMetricRecord; // for TradeCommodityMetricRecord if needed

// VTABLE: IMPERIALISM 0x666110
class TIndustryAmtBar : public TAmtBar {
public:
  struct TradeCommodityMetricRecord* selectedMetricRecord;

  TIndustryAmtBar();
  virtual ~TIndustryAmtBar();

  void DoPostCreate(struct TDocument* document);
  void DrawAmt();
};
