#pragma once

#include "game/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00663318
class TArrowsControl : public TPicture {
public:
  DECLARE_DYNCREATE(TArrowsControl)
  virtual ~TArrowsControl() override; // slot 0x01 (scalar deleting destructor)
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint,
                          unsigned char commandFlag) override; // slot 0x68 0x5839f0
  int timingDword90;

  TArrowsControl();
};

ASSERT_SIZE(TArrowsControl, 0x94);
