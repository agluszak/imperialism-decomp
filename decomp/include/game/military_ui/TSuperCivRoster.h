#pragma once

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064d778
class TSuperCivRoster : public TPageView {
public:
  DECLARE_DYNCREATE(TSuperCivRoster)
  virtual ~TSuperCivRoster() override; // slot 0x01 (scalar deleting destructor)
  // Builds the ledger roster pages into the owning view context. Args 2 and 3 are the
  // frame OFFSET and SIZE, forwarded straight to InitializeUiResourceEntryFrameAndParent;
  // the caller (0x005dde05/0x005dde06) pushes &size then &offset out of one adjacent
  // 4-int block, so right-to-left arg2 = {0xd,0x2e} and arg3 = {0x1ca,0x136}. An earlier
  // model read arg3 as a TView** out-parameter, which the call site does not support.
  virtual void InitializeLedgerRosterPages(TView* pOwnerContext, int* pOffsetLayout,
                                           int* pSizeLayout); // slot 0x6e 0x4ab470

  // Object slice from the inline-expanded ctor at 0x5ddde1 (inside
  // TViewMgr::ShowCivilianLedgerDialogAndSelectUnit): base TPageView ctor, own vptr,
  // then the selected-entry index seeded to -1. Fields between the TPageView slice
  // and +0x84 are not yet recovered.
  // +0x84: the selected civilian's map tile index (-1 = none). TMiniCivView::DoEvent
  // (0x4ac320) stores civUnit84->tileIndex06 here, and the ledger driver feeds it
  // straight to NoticeTile, so both ends agree it is a tile index.
  short selectedTileIndex84;

  // Defined inline: the original constructor exists only inline-expanded at its
  // call sites (TPageView ctor call + vptr store + selectedTileIndex84 = -1).
  TSuperCivRoster() : TPageView() {
    selectedTileIndex84 = -1;
  }
};

ASSERT_SIZE(TSuperCivRoster, 0x88);
