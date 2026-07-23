#pragma once

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00644970
class TGameScorePicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TGameScorePicture)
  virtual ~TGameScorePicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0057b620
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x57b0a0

  TGameScorePicture();
};
