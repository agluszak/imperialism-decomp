#pragma once

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064d778
class TSuperCivRoster : public TPageView {
public:
  DECLARE_DYNCREATE(TSuperCivRoster)
  virtual ~TSuperCivRoster() override; // slot 0x01 (scalar deleting destructor)
  // Builds the ledger roster pages into the owning view context and tracks the
  // running dialog through pOutDialogView (verified 3-arg thiscall, RET 0xC; the
  // old ConstructTSuperCivRosterBaseState name was a misread — this is not a ctor).
  virtual void InitializeLedgerRosterPages(TView* pOwnerContext, int* pBoundsRect,
                                           TView** pOutDialogView); // slot 0x6e 0x4ab470

  // Object slice from the inline-expanded ctor at 0x5ddde1 (inside
  // TViewMgr::ShowCivilianLedgerDialogAndSelectUnit): base TPageView ctor, own vptr,
  // then the selected-entry index seeded to -1. Fields between the TPageView slice
  // and +0x84 are not yet recovered.
  short selectedIndex84; // +0x84 (selected civilian index; -1 = none)

  // Defined inline: the original constructor exists only inline-expanded at its
  // call sites (TPageView ctor call + vptr store + selectedIndex84 = -1).
  TSuperCivRoster() : TPageView() {
    selectedIndex84 = -1;
  }
};

ASSERT_SIZE(TSuperCivRoster, 0x88);
