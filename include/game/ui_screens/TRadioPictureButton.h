#pragma once

#include "game/ui_screens/TUpDownPictureButton.h"

// VTABLE: IMPERIALISM 0x0065f670
class TRadioPictureButton : public TUpDownPictureButton {
public:
  DECLARE_DYNCREATE(TRadioPictureButton)
  virtual ~TRadioPictureButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;                          // slot 0x0f 0x00571850
  virtual undefined OrphanCallChain_C2_I16_005718f0(int arg1, int arg2); // slot 0x74 0x5718f0
  short reserved94;

  TRadioPictureButton();
};
