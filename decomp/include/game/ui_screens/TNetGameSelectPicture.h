#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00661fb0
class TNetGameSelectPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TNetGameSelectPicture)
  virtual ~TNetGameSelectPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00576bc0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x576b90

  // NOOP: verified empty in original 0x00576ad6 (no standalone TNetGameSelectPicture::TNetGameSelectPicture body exists: CreateObject 0x00576aa0 inlines this default ctor, calling the TNoHilitePicture base ctor directly at that site)
  TNetGameSelectPicture() {}
};
ASSERT_SIZE(TNetGameSelectPicture, 0x94);
