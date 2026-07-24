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

  // NOOP: verified empty in original 0x0056b7b6 (no standalone TGameInfoPicture::TGameInfoPicture body exists: CreateObject 0x0056b780 inlines this default ctor, calling the TPicture base ctor directly at that site)
  TGameInfoPicture() {}
};
ASSERT_SIZE(TGameInfoPicture, 0x90);
