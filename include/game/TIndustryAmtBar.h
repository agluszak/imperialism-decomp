#pragma once

#include "game/TAmtBar.h"
#include "game/TradeCommodityMetricRecord.h"

// VTABLE: IMPERIALISM 0x666110
struct CRuntimeClass;
class TIndustryAmtBar : public TAmtBar {
public:
  TradeCommodityMetricRecord* selectedMetricRecord;

  TIndustryAmtBar();
  virtual ~TIndustryAmtBar();
  CRuntimeClass* GetRuntimeClass() override;

  void DoPostCreate(struct TDocument* document);
  void DrawAmt();
};
