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
};

ASSERT_SIZE(TCtlMgr, 0x84);
