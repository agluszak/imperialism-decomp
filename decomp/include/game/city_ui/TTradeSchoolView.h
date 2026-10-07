#pragma once

#include "compat.h"
#include "game/city_ui/TIndustryView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00652690
class TTradeSchoolView : public TIndustryView {
public:
  DECLARE_DYNCREATE(TTradeSchoolView)
  virtual ~TTradeSchoolView() override;
  virtual void DoStartup() override;
  virtual void UpdateFields() override;

  TTradeSchoolView();
};

ASSERT_SIZE(TTradeSchoolView, 0xa8);
