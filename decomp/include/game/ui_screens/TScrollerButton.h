#pragma once

#include "compat.h"

#include "game/ui_screens/TPictureButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006616e8
class TScrollerButton : public TPictureButton {
public:
  DECLARE_DYNCREATE(TScrollerButton)
  virtual ~TScrollerButton() override;
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, bool commandFlag) override;

  TScrollerButton();
};
ASSERT_SIZE(TScrollerButton, 0x94);
