#pragma once

#include "compat.h"

#include "game/ui_screens/TPictureButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065f8a8
class TOnOffRadioButton : public TPictureButton {
public:
  DECLARE_DYNCREATE(TOnOffRadioButton)
  virtual ~TOnOffRadioButton() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void SetState(bool on, bool drawImmediate);

  TOnOffRadioButton();

  unsigned char state94;
  unsigned char padding95[3];
};
ASSERT_SIZE(TOnOffRadioButton, 0x98);
