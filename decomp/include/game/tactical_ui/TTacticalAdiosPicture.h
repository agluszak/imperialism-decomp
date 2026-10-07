#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00645428
class TTacticalAdiosPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TTacticalAdiosPicture)
  virtual ~TTacticalAdiosPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  // NOOP: verified empty in original 0x005ad466
  TTacticalAdiosPicture() {}
};
ASSERT_SIZE(TTacticalAdiosPicture, 0x90);
