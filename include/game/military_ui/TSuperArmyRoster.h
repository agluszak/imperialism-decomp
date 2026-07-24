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

  // RESOLVED (bd 7v4): one domain, the city-record index (0..0x180 rows of
  // TMapMgr::cityScoreTable, a.k.a. province row). The apparent conflict came from
  // TUnit::tileIndex06's doc: for TMilitaryUnit that field holds the stationed
  // city-record index, not a raw map tile (same finding as TMapMgr.cpp 0x518d90).
  //  - writer 0x4ab2e8 (TMiniArmyView::DoEvent) stores militaryUnit84->tileIndex06
  //    (city-record index for military units);
  //  - reader 0x5dda30 (TViewMgr army-ledger driver) passes it to TArmyMgr::
  //    SetActiveProvinceSelection, whose body indexes cityScoreTable[v] bounded by
  //    0x180, and reads cityScoreTable[v] at stride 0xa8 itself.
  // The sibling TSuperCivRoster's +0x84 really is a map-tile index — different class,
  // different domain. -1 means no selection.
  short selectedCityRecordIndex84;
  short pad86;

  // The original constructor exists only inline-expanded at its callers: base page ctor,
  // own vptr, then selectedCityRecordIndex84 = -1.
  TSuperArmyRoster() : TPageView() {
    selectedCityRecordIndex84 = -1;
  }
};

ASSERT_SIZE(TSuperArmyRoster, 0x88);
