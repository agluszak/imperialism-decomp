#pragma once

#include "compat.h"
#include "game/mfc.h"

class TControl;

void __cdecl CopyCurrentMouseCapturePoint(CPoint* outPoint);

class TMouseCaptureState {
public:
  TMouseCaptureState() : capturedControl(0) {}
  ~TMouseCaptureState() {
    if (capturedControl != 0) {
      capturedControl = 0;
      ::ReleaseCapture();
    }
  }

  CPoint startPoint;         // 0x00 point DoMouseCommand latched
  CPoint lastPoint;          // 0x08 previous currentPoint, shifted down on each update
  CPoint currentPoint;       // 0x10 latest tracked point
  TControl* capturedControl; // 0x18 the control owning the capture; null when inactive

  void BeginMouseCaptureForControlAndStartRepeatTimer(CPoint* point, TControl* control);
  void NotifyCaptureOwnerState1AndMaybeUpdateCoords(unsigned int nFlags, int x, int y);
  void EndMouseCaptureAndStopRepeatTimer(unsigned int nFlags, int x, int y);

  void CopyCurrentPointTo(CPoint* out);
};

ASSERT_SIZE(TMouseCaptureState, 0x1c);

VOID CALLBACK NotifyGlobalCaptureOwnerState1WithCachedCoords(HWND hwnd, UINT message, UINT timerId,
                                                             DWORD tickCount);
