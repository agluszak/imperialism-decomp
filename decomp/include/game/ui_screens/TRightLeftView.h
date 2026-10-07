#pragma once

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00663990
class TRightLeftView : public TControl {
public:
  DECLARE_DYNCREATE(TRightLeftView)
  virtual ~TRightLeftView() override;
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, bool commandFlag) override;

  int repeatTick;

  TRightLeftView();
};

ASSERT_SIZE(TRightLeftView, 0x88);
