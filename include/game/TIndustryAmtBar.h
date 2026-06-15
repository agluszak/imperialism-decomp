#pragma once

#include "game/TAmtBar.h"
#include "game/TradeCommodityMetricRecord.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666110
class TIndustryAmtBar : public TAmtBar {
public:
  TradeCommodityMetricRecord* selectedMetricRecord;

  TIndustryAmtBar();
  // ~TIndustryAmtBar is compiler-generated (implicit virtual dtor).
  CRuntimeClass* GetRuntimeClass() override;

  void DoPostCreate(struct TDocument* document);
  void DrawAmt();
};
