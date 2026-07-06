#pragma once

#include "compat.h"
#include "game/TControl.h"

// Control manager base class (vtable via TButton family).
// Base recovered from CRuntimeClass descriptor: TCtlMgr -> TControl -> TView -> TEventHandler -> TObject -> CObject.
class TCtlMgr : public TControl {
public:
  DECLARE_DYNCREATE(TCtlMgr)

  TCtlMgr();
};

ASSERT_SIZE(TCtlMgr, 0x84);
