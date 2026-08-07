#pragma once

#include "compat.h"
#include "game/city_ui/TIndustryView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00652690
class TTradeSchoolView : public TIndustryView {
public:
  DECLARE_DYNCREATE(TTradeSchoolView)
  virtual ~TTradeSchoolView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoStartup() override;    // slot 0x75 0x4cd8d0
  virtual void UpdateFields() override; // slot 0x76 0x4ce070
  // RTTI oracle: sizeof(TTradeSchoolView) == 0xa8, identical to TIndustryView -- this
  // class adds no data members of its own. Its ctor (0x4cd840) re-runs exactly
  // TIndustryView's field init (city94/unresolvedZeroA0/selectedIndustryUnitTypeA4)
  // via the inlined base body.

  TTradeSchoolView();
};

ASSERT_SIZE(TTradeSchoolView, 0xa8);
