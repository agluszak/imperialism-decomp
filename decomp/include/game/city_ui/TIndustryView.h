#pragma once

#include "compat.h"
#include "game/city_ui/TBuildingView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00652448
class TIndustryView : public TBuildingView {
public:
  DECLARE_DYNCREATE(TIndustryView)
  virtual ~TIndustryView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoStartup() override;
  virtual void UpdateFields() override;
  int unresolvedZero;
  short selectedIndustryUnitType;

  TIndustryView();
};

ASSERT_SIZE(TIndustryView, 0xa8);
