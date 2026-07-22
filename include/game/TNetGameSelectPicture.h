#pragma once

#include "game/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00661fb0
class TNetGameSelectPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TNetGameSelectPicture)
  virtual ~TNetGameSelectPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00576bc0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x576b90

  TNetGameSelectPicture();
};
