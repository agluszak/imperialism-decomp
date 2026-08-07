#pragma once

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00663990
class TRightLeftView : public TControl {
public:
  DECLARE_DYNCREATE(TRightLeftView)
  virtual ~TRightLeftView() override; // slot 0x01 (scalar deleting destructor)
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint,
                          unsigned char commandFlag) override; // slot 0x68 0x583fb0

  int timingDword84;

  TRightLeftView();
};

ASSERT_SIZE(TRightLeftView, 0x88);
