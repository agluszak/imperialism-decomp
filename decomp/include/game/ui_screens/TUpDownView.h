#pragma once

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00663770
class TUpDownView : public TControl {
public:
  DECLARE_DYNCREATE(TUpDownView)
  virtual ~TUpDownView() override; // slot 0x01 (scalar deleting destructor)
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint,
                          unsigned char commandFlag) override; // slot 0x68 0x583dd0
  int timingDword84;

  TUpDownView();
};

ASSERT_SIZE(TUpDownView, 0x88);
