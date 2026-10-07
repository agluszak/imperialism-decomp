#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065def8
class TGameInfoPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TGameInfoPicture)
  virtual ~TGameInfoPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  // NOOP: verified empty in original 0x0056b7b6
  TGameInfoPicture() {}
};
ASSERT_SIZE(TGameInfoPicture, 0x90);
