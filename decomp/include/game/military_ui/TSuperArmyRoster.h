#pragma once

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064d2f8
class TSuperArmyRoster : public TPageView {
public:
  DECLARE_DYNCREATE(TSuperArmyRoster)
  virtual ~TSuperArmyRoster() override;
  virtual void PopulateArmyOrderPageEntries(TView* panel, int* offsetLayout, int* sizeLayout);

  short selectedCityRecordIndex;
  short pad86;

  TSuperArmyRoster() {
    selectedCityRecordIndex = -1;
  }
};

ASSERT_SIZE(TSuperArmyRoster, 0x88);
