#pragma once

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064d778
class TSuperCivRoster : public TPageView {
public:
  DECLARE_DYNCREATE(TSuperCivRoster)
  virtual ~TSuperCivRoster() override;
  virtual void InitializeLedgerRosterPages(TView* pOwnerContext, int* pOffsetLayout,
                                           int* pSizeLayout);

  short selectedTileIndex;

  TSuperCivRoster() : TPageView() {
    selectedTileIndex = -1;
  }
};

ASSERT_SIZE(TSuperCivRoster, 0x88);
