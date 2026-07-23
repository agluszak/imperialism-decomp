#pragma once

#include "game/TPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064d2f8
class TSuperArmyRoster : public TPageView {
public:
  DECLARE_DYNCREATE(TSuperArmyRoster)
  virtual ~TSuperArmyRoster() override; // slot 0x01 (scalar deleting destructor)
  virtual void PopulateArmyOrderPageEntries(TView* panel, int* offsetLayout,
                                            int* sizeLayout); // slot 0x6e 0x4aa540

  // UNRESOLVED_FIELD_ATTRIBUTION: +0x84 has two conflicting readings.
  //  - writer  0x4ab2e8 (TMiniArmyView::DoEvent) stores militaryUnit84->tileIndex06,
  //    which TUnit documents as a map tile index;
  //  - reader  0x5dda30 (TViewMgr's army-ledger driver) uses it as a province row:
  //    SetActiveProvinceSelection(v) and cityScoreTable[v].cityTileIndex04.
  // The sibling TSuperCivRoster's +0x84 is unambiguously a tile index at both ends, so
  // this is not simply the same field. Kept provisionally named after the reader until
  // the two domains are reconciled. -1 means no selection.
  short selectedIndex84;
  short pad86;

  // The original constructor exists only inline-expanded at its callers: base page ctor,
  // own vptr, then selectedIndex84 = -1.
  TSuperArmyRoster() : TPageView() {
    selectedIndex84 = -1;
  }
};

ASSERT_SIZE(TSuperArmyRoster, 0x88);
