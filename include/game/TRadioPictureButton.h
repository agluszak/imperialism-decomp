#pragma once

#include "game/TUpDownPictureButton.h"

// VTABLE: IMPERIALISM 0x0065f670
class TRadioPictureButton : public TUpDownPictureButton {
public:
  DECLARE_DYNCREATE(TRadioPictureButton)
  virtual ~TRadioPictureButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00571850
  // Mac CodeWarrior identity: TRadioPictureButton::SetState(unsigned char, unsigned char).
  // Named SetRadioState here because Windows gives it its own slot rather than
  // overriding TView::SetState(int, int) at slot 0x2a.
  virtual void SetRadioState(unsigned char state, unsigned char refreshNow); // slot 0x74 0x5718f0
  short reserved94;

  TRadioPictureButton();
};
