#pragma once

#include "compat.h"

#include "game/ui_screens/TUpDownPictureButton.h"

// VTABLE: IMPERIALISM 0x0065f670
class TRadioPictureButton : public TUpDownPictureButton {
public:
  DECLARE_DYNCREATE(TRadioPictureButton)
  virtual ~TRadioPictureButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00571850
  // Mac CodeWarrior identity: TRadioPictureButton::SetState(unsigned char, unsigned char).
  // Windows gives it its own slot after the picture-button interface.
  virtual void SetRadioState(unsigned char state, unsigned char refreshNow); // slot 0x74 0x5718f0
  // The ctor (0x5717c0) zeroes a single byte at +0x94; the rest is layout padding.
  unsigned char reserved94;
  unsigned char padding95[3];

  TRadioPictureButton();
};
ASSERT_SIZE(TRadioPictureButton, 0x98);
