#pragma once

#include "compat.h"
#include "game/ui_core/TControl.h"

// VTABLE: IMPERIALISM 0x0064a2b8
class TCtlMgr : public TControl {
public:
  // NOOP: verified empty in original 0x0048ea37
  DECLARE_DYNCREATE(TCtlMgr)

  TCtlMgr() {}

  virtual ~TCtlMgr() override; // slot 0x01 (scalar deleting destructor 0x492de0)

  virtual void AssertMcAppUiInvalidationFlagSet(int arg1, int arg2); // slot 0x71 0x492db0
};

ASSERT_SIZE(TCtlMgr, 0x84);
