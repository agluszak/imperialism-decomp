#pragma once

#include "compat.h"
#include "game/TUpDownPictureButton.h"

// VTABLE: IMPERIALISM 0x663540
class TSidewaysArrow : public TUpDownPictureButton {
public:
  DECLARE_DYNCREATE(TSidewaysArrow) // GetRuntimeClass slot 0x00 0x583b30
  TSidewaysArrow();
  int repeatDeadlineTick; // 0x94

  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint,
                          unsigned char commandFlag) override; // slot 0x68 0x583bd0
};

ASSERT_SIZE(TSidewaysArrow, 0x98);
