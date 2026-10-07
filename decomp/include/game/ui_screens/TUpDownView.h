#pragma once

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00663770
class TUpDownView : public TControl {
public:
  DECLARE_DYNCREATE(TUpDownView)
  virtual ~TUpDownView() override;
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, bool commandFlag) override;
  int repeatTick;

  TUpDownView();
};

ASSERT_SIZE(TUpDownView, 0x88);
