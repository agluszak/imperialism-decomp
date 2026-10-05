#pragma once

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064d778
class TSuperCivRoster : public TPageView {
public:
  DECLARE_DYNCREATE(TSuperCivRoster)
  virtual ~TSuperCivRoster() override; // slot 0x01 (scalar deleting destructor)
  virtual void InitializeLedgerRosterPages(TView* pOwnerContext, int* pOffsetLayout,
                                           int* pSizeLayout); // slot 0x6e 0x4ab470

  short selectedTileIndex;

  TSuperCivRoster() : TPageView() {
    selectedTileIndex = -1;
  }
};

ASSERT_SIZE(TSuperCivRoster, 0x88);
