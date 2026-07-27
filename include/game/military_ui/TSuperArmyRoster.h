#pragma once

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064d2f8
class TSuperArmyRoster : public TPageView {
public:
  DECLARE_DYNCREATE(TSuperArmyRoster)
  virtual ~TSuperArmyRoster() override; // slot 0x01 (scalar deleting destructor)
  virtual void PopulateArmyOrderPageEntries(TView* panel, int* offsetLayout,
                                            int* sizeLayout); // slot 0x6e 0x4aa540

  // City-record index into TMapMgr::cityScoreTable (0..0x17f); -1 means no selection.
  // TMilitaryUnit::tileIndex06 carries the same city-record domain at this call site.
  short selectedCityRecordIndex84;
  short pad86;

  // The original constructor exists only inline-expanded at its callers: base page ctor,
  // own vptr, then selectedCityRecordIndex84 = -1.
  TSuperArmyRoster() : TPageView() {
    selectedCityRecordIndex84 = -1;
  }
};

ASSERT_SIZE(TSuperArmyRoster, 0x88);
