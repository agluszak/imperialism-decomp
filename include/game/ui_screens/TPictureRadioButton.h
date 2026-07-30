#pragma once

#include "compat.h"

#include "game/ui_screens/TToggleButton.h"
#include "game/mfc.h"

#if defined(__clang__)
#pragma clang diagnostic push
// Windows retains TView::ViewEnable(int, int) at slot 0x2a and adds this byte overload at 0x75.
#pragma clang diagnostic ignored "-Woverloaded-virtual"
#endif

// VTABLE: IMPERIALISM 0x0065ed98
class TPictureRadioButton : public TToggleButton {
public:
  DECLARE_DYNCREATE(TPictureRadioButton)
  virtual ~TPictureRadioButton() override; // slot 0x01 (scalar deleting destructor)
  virtual char HandleMouseDown(const CPoint& point, TToolboxEvent* event,
                               CPoint origin) override;            // slot 0x46 0x570fb0
  virtual void Select(bool isPressed, bool notifyParent) override; // slot 0x74 0x570f40
  virtual void ViewEnable(char isEnabled, char refreshNow);        // slot 0x75 0x570de0
  virtual void DefaultSize(bool refreshNow);                       // slot 0x76 0x570ea0

  TPictureRadioButton();
};
ASSERT_SIZE(TPictureRadioButton, 0x90);

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
