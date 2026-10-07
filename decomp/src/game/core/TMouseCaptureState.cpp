#include "game/core/TMouseCaptureState.h"

#include "game/ui_core/TControl.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

// FUNCTION: IMPERIALISM 0x00489b60
VOID CALLBACK NotifyGlobalCaptureOwnerState1WithCachedCoords(HWND hwnd, UINT message, UINT timerId,
                                                             DWORD tickCount) {
  (void)hwnd;
  (void)message;
  (void)timerId;
  (void)tickCount;
  TControl* captured = g_McAppMouseCaptureState.capturedControl;
  if (captured != 0) {
    CPoint scratchPoint(0, 0);
    captured->WindowToLocal(&scratchPoint);
    g_McAppMouseCaptureState.lastPoint = g_McAppMouseCaptureState.currentPoint;
    captured->TrackMouse(kTrackPhaseUpdate, g_McAppMouseCaptureState.startPoint,
                         g_McAppMouseCaptureState.lastPoint, g_McAppMouseCaptureState.currentPoint,
                         true);
  }
}

// FUNCTION: IMPERIALISM 0x00489bf0
void TMouseCaptureState::BeginMouseCaptureForControlAndStartRepeatTimer(CPoint* point,
                                                                        TControl* control) {
  capturedControl = control;
  CWnd::FromHandle(::SetCapture(control->nativeWindow->m_hWnd));
  startPoint = *point;
  lastPoint = *point;
  currentPoint = *point;
  control->TrackMouse(kTrackPhaseBegin, startPoint, lastPoint, currentPoint, true);
  if (g_McAppUiMouseCaptureTimerId == 0) {
    g_McAppUiMouseCaptureTimerId = ::SetTimer(control->nativeWindow->m_hWnd, 0xef, 0x11,
                                              NotifyGlobalCaptureOwnerState1WithCachedCoords);
  }
}

// FUNCTION: IMPERIALISM 0x00489cb0
void TMouseCaptureState::NotifyCaptureOwnerState1AndMaybeUpdateCoords(unsigned int nFlags, int x,
                                                                      int y) {
  if (capturedControl == 0) {
    return;
  }
  CPoint ownerRelativePoint(x, y);
  capturedControl->WindowToLocal(&ownerRelativePoint);
  lastPoint = currentPoint;
  if ((nFlags & 0x20) == 0) {
    currentPoint = ownerRelativePoint;
  }
  capturedControl->TrackMouse(kTrackPhaseUpdate, startPoint, lastPoint, currentPoint, true);
}

// FUNCTION: IMPERIALISM 0x00489d40
void TMouseCaptureState::EndMouseCaptureAndStopRepeatTimer(unsigned int nFlags, int x, int y) {
  (void)nFlags;
  if (capturedControl == 0) {
    return;
  }
  if (g_McAppUiMouseCaptureTimerId != 0) {
    ::KillTimer(capturedControl->nativeWindow->m_hWnd, g_McAppUiMouseCaptureTimerId);
    g_McAppUiMouseCaptureTimerId = 0;
  }
  ::ReleaseCapture();
  CPoint ownerRelativePoint(x, y);
  capturedControl->WindowToLocal(&ownerRelativePoint);
  lastPoint = currentPoint;
  // Owner-relative, as in Notify... above (0x489db2 reloads the converted stack local).
  currentPoint = ownerRelativePoint;
  capturedControl->TrackMouse(kTrackPhaseEnd, startPoint, lastPoint, currentPoint, true);
  capturedControl = 0;
}

// FUNCTION: IMPERIALISM 0x00489e10
void TMouseCaptureState::CopyCurrentPointTo(CPoint* out) {
  LONG x = currentPoint.x;
  LONG y = currentPoint.y;
  out->x = x;
  out->y = y;
}

// Copies the global mouse-capture state's latest tracked point into the caller's buffer.
// FUNCTION: IMPERIALISM 0x00489e40
void __cdecl CopyCurrentMouseCapturePoint(CPoint* out) {
  // Loads both members then stores both, matching the original's POD point copy.
  LONG y = g_McAppMouseCaptureState.currentPoint.y;
  LONG x = g_McAppMouseCaptureState.currentPoint.x;
  out->x = x;
  out->y = y;
}
