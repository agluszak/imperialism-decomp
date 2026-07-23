#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065def8
class TGameInfoPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TGameInfoPicture)
  virtual ~TGameInfoPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0056b9b0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x56b870

  TGameInfoPicture();
};
ASSERT_SIZE(TGameInfoPicture, 0x90);
