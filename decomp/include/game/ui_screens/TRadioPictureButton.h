#pragma once

#include "compat.h"

#include "game/ui_screens/TUpDownPictureButton.h"

// VTABLE: IMPERIALISM 0x0065f670
class TRadioPictureButton : public TUpDownPictureButton {
public:
  DECLARE_DYNCREATE(TRadioPictureButton)
  virtual ~TRadioPictureButton() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void SetState(bool state, bool refreshNow);
  // The ctor (0x5717c0) zeroes a single byte at +0x94; the rest is layout padding.
  unsigned char reserved94;
  unsigned char padding95[3];

  TRadioPictureButton();
};
ASSERT_SIZE(TRadioPictureButton, 0x98);
