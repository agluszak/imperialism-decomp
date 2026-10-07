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

  CPoint startPoint;         // point DoMouseCommand latched
  CPoint lastPoint;          // previous currentPoint, shifted down on each update
  CPoint currentPoint;       // latest tracked point
  TControl* capturedControl; // the control owning the capture; null when inactive

  void BeginTracking(CPoint* point, TControl* control);
  void NotifyTracking(unsigned int nFlags, int x, int y);
  void EndMouseCaptureAndStopRepeatTimer(unsigned int nFlags, int x, int y);

  void CopyCurrentPointTo(CPoint* out);
};

ASSERT_SIZE(TMouseCaptureState, 0x1c);

VOID CALLBACK NotifyCaptureOwner(HWND hwnd, UINT message, UINT timerId, DWORD tickCount);
