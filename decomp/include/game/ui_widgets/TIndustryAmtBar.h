#pragma once

#include "compat.h"

#include "game/ui_widgets/TAmtBar.h"

class TProductionOrder;

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666110
class TIndustryAmtBar : public TAmtBar {
public:
  // FUNCTION: IMPERIALISM 0x00589240
  ~TIndustryAmtBar() override {}
  TProductionOrder* selectedMetricRecord;

  TIndustryAmtBar();
  // ~TIndustryAmtBar is compiler-generated (implicit virtual dtor).
  DECLARE_DYNCREATE(TIndustryAmtBar)
  void DoPostCreate(int arg) override;
  void DrawAmt() override;
  virtual void DrawMax(short selectedValue); // 0x00589540
};
ASSERT_SIZE(TIndustryAmtBar, 0x6c);
