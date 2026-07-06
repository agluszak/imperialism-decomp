#pragma once

#include "compat.h"
#include "game/mfc.h"

class TControl;

// McApp UI singleton tracking an in-progress mouse capture/drag, originally 4 loose
// globals @ 0x6a1a68-0x6a1a83 (the repeat-timer id @ 0x6a1adc is a separate global, not
// part of this object). No vtable/RTTI observed for it -- a plain data class with two
// real __thiscall methods (ecx = &g_McAppMouseCaptureState).
class TMouseCaptureState {
public:
  CPoint startPoint;         // 0x00 point BeginMouseCaptureAndStartRepeatTimer latched
  CPoint lastPoint;          // 0x08 previous currentPoint, shifted down on each update
  CPoint currentPoint;       // 0x10 latest tracked point
  TControl* capturedControl; // 0x18 the control owning the capture; null when inactive

  void NotifyCaptureOwnerState1AndMaybeUpdateCoords(unsigned int nFlags, int x, int y);
  void EndMouseCaptureAndStopRepeatTimer(unsigned int nFlags, int x, int y);
};

ASSERT_SIZE(TMouseCaptureState, 0x1c);
