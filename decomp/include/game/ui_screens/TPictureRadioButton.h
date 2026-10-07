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
  virtual ~TPictureRadioButton() override;
  virtual bool HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void Select(bool isPressed, bool notifyParent) override;
  virtual void ViewEnable(char isEnabled, char refreshNow);
  virtual void DefaultSize(bool refreshNow);

  TPictureRadioButton();
};
ASSERT_SIZE(TPictureRadioButton, 0x90);

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
