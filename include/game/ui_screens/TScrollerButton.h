#pragma once

#include "game/ui_screens/TPictureButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006616e8
class TScrollerButton : public TPictureButton {
public:
  DECLARE_DYNCREATE(TScrollerButton)
  virtual ~TScrollerButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint,
                          unsigned char commandFlag) override; // slot 0x68 0x574fc0

  TScrollerButton();
};
