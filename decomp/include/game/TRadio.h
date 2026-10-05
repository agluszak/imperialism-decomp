#pragma once

#include "game/TCtlMgr.h"

// VTABLE: IMPERIALISM 0x0064a708
class TRadio : public TCtlMgr {
public:
  DECLARE_DYNCREATE(TRadio)

  TRadio() : TCtlMgr() {}

  virtual ~TRadio() override; // slot 0x01 (scalar deleting destructor 0x48edd0)
};

ASSERT_SIZE(TRadio, 0x84);
