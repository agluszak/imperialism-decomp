#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00661fb0
class TNetGameSelectPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TNetGameSelectPicture)
  virtual ~TNetGameSelectPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  // NOOP: verified empty in original 0x00576ad6
  TNetGameSelectPicture() {}
};
ASSERT_SIZE(TNetGameSelectPicture, 0x94);
