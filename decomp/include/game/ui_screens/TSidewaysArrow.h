#pragma once

#include "compat.h"
#include "game/ui_screens/TUpDownPictureButton.h"

// VTABLE: IMPERIALISM 0x663540
class TSidewaysArrow : public TUpDownPictureButton {
public:
  // FUNCTION: IMPERIALISM 0x00583bb0
  ~TSidewaysArrow() override {}
  DECLARE_DYNCREATE(TSidewaysArrow) // GetRuntimeClass slot 0x00
  TSidewaysArrow();
  int repeatDeadlineTick;

  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, bool commandFlag) override;
};

ASSERT_SIZE(TSidewaysArrow, 0x98);
