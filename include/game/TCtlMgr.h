#pragma once

#include "compat.h"
#include "game/TControl.h"

// Control manager base class.
// Base recovered from CRuntimeClass descriptor: TCtlMgr -> TControl -> TView -> TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064a2b8
class TCtlMgr : public TControl {
public:
  DECLARE_DYNCREATE(TCtlMgr)

  TCtlMgr();
  virtual ~TCtlMgr() override; // slot 0x01 (scalar deleting destructor 0x492de0)
};

ASSERT_SIZE(TCtlMgr, 0x84);
