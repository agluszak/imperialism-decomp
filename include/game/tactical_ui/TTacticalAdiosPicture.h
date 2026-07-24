#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00645428
class TTacticalAdiosPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TTacticalAdiosPicture)
  virtual ~TTacticalAdiosPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005ad650
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x5ad4d0

  TTacticalAdiosPicture();
};
ASSERT_SIZE(TTacticalAdiosPicture, 0x90);
