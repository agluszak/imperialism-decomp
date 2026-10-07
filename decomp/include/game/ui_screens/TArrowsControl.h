#pragma once

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00663318
class TArrowsControl : public TPicture {
public:
  DECLARE_DYNCREATE(TArrowsControl)
  virtual ~TArrowsControl() override;
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, bool commandFlag) override;
  int nextRepeatTick;

  TArrowsControl();
};

ASSERT_SIZE(TArrowsControl, 0x94);
