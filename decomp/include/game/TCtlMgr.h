#pragma once

#include "compat.h"
#include "game/ui_core/TControl.h"

// Control manager base class.
// Base recovered from CRuntimeClass descriptor: TCtlMgr -> TControl -> TView -> TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064a2b8
class TCtlMgr : public TControl {
public:
  DECLARE_DYNCREATE(TCtlMgr)

  // In-class inline: the original has no out-of-line TCtlMgr::TCtlMgr -- every
  // caller absorbs it, so an out-of-line definition pessimizes them into a call.
  // NOOP: verified empty in original 0x0048ea37 (no standalone TCtlMgr::TCtlMgr body exists: CreateObject 0x0048ea00 inlines this default ctor, calling the TView base ctor directly at that site)
  TCtlMgr() {}

  virtual ~TCtlMgr() override; // slot 0x01 (scalar deleting destructor 0x492de0)

  // Assert-only virtual default (slot 0x71, RET 0x8): asserts the one-shot
  // McAppUI flag at 0x6a1b5c (header path, line 0x5a7) and returns. The five
  // leaf vtables that inherit it (TButton/TRadio family) share thunk 0x4096f6.
  virtual void AssertMcAppUiInvalidationFlagSet(int arg1, int arg2); // slot 0x71 0x492db0
};

ASSERT_SIZE(TCtlMgr, 0x84);
