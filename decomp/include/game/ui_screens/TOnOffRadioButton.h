#pragma once

#include "compat.h"

#include "game/ui_screens/TPictureButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065f8a8
class TOnOffRadioButton : public TPictureButton {
public:
  DECLARE_DYNCREATE(TOnOffRadioButton)
  virtual ~TOnOffRadioButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00571a80
  virtual void SetState(bool on,
                        bool drawImmediate); // slot 0x74 0x571b20

  TOnOffRadioButton();

  unsigned char state94;
  unsigned char padding95[3];
};
ASSERT_SIZE(TOnOffRadioButton, 0x98);
