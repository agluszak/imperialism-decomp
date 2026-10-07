#pragma once

#include "game/TCtlMgr.h"

// VTABLE: IMPERIALISM 0x0064a708
class TRadio : public TCtlMgr {
public:
  DECLARE_DYNCREATE(TRadio)

  TRadio() : TCtlMgr() {}

  virtual ~TRadio() override;
};

ASSERT_SIZE(TRadio, 0x84);
