#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00644970
class TGameScorePicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TGameScorePicture)
  virtual ~TGameScorePicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  TGameScorePicture();
};
ASSERT_SIZE(TGameScorePicture, 0x94);
