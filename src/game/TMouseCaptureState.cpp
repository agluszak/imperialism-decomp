#include "game/TMouseCaptureState.h"

#include "game/TControl.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x00489b60
VOID CALLBACK NotifyGlobalCaptureOwnerState1WithCachedCoords(HWND hwnd, UINT message, UINT timerId,
                                                             DWORD tickCount) {
  (void)hwnd;
  (void)message;
  (void)timerId;
  (void)tickCount;
  TControl* captured = g_McAppMouseCaptureState.capturedControl;
  if (captured != 0) {
    // Ground truth passes a zeroed stack point through the owner-relative conversion and
    // discards it; only the dispatch side effects matter on the repeat tick.
    CPoint scratchPoint(0, 0);
    captured->WindowToLocal(&scratchPoint);
    g_McAppMouseCaptureState.lastPoint = g_McAppMouseCaptureState.currentPoint;
    captured->DispatchPictureResourceCommand(1, &g_McAppMouseCaptureState.startPoint,
                                             &g_McAppMouseCaptureState.lastPoint,
                                             &g_McAppMouseCaptureState.currentPoint, 1);
  }
}

// State-side twin of TControl::BeginMouseCaptureAndStartRepeatTimer (no static callers in
// the original binary; kept by the linker). Latches the capture on `control`, seeds all
// three cached points from `point`, sends the state-0 (begin) picture-resource command,
// and arms the shared 17ms repeat timer.
// FUNCTION: IMPERIALISM 0x00489bf0
void TMouseCaptureState::BeginMouseCaptureForControlAndStartRepeatTimer(CPoint* point,
                                                                        TControl* control) {
  capturedControl = control;
  CWnd::FromHandle(::SetCapture(control->nativeWindow50->m_hWnd));
  startPoint = *point;
  lastPoint = *point;
  currentPoint = *point;
  control->DispatchPictureResourceCommand(0, &startPoint, &lastPoint, &currentPoint, 1);
  if (g_McAppUiMouseCaptureTimerId_006A1ADC == 0) {
    g_McAppUiMouseCaptureTimerId_006A1ADC =
        ::SetTimer(control->nativeWindow50->m_hWnd, 0xef, 0x11,
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
  // Ground truth gates this on bit 0x20 of nFlags (MK_XBUTTON1 in the standard WM_MOUSEMOVE
  // flag set); the exact intent of skipping the coordinate update on that bit isn't recovered.
  // The stored point is the owner-relative one (0x489cf5 reloads the converted stack local,
  // not the raw args).
  if ((nFlags & 0x20) == 0) {
    currentPoint = ownerRelativePoint;
  }
  capturedControl->DispatchPictureResourceCommand(1, &startPoint, &lastPoint, &currentPoint, 1);
}

// FUNCTION: IMPERIALISM 0x00489d40
void TMouseCaptureState::EndMouseCaptureAndStopRepeatTimer(unsigned int nFlags, int x, int y) {
  (void)nFlags;
  if (capturedControl == 0) {
    return;
  }
  if (g_McAppUiMouseCaptureTimerId_006A1ADC != 0) {
    ::KillTimer(reinterpret_cast<HWND>(capturedControl->nativeWindow50->m_hWnd),
                g_McAppUiMouseCaptureTimerId_006A1ADC);
    g_McAppUiMouseCaptureTimerId_006A1ADC = 0;
  }
  ::ReleaseCapture();
  CPoint ownerRelativePoint(x, y);
  capturedControl->WindowToLocal(&ownerRelativePoint);
  lastPoint = currentPoint;
  // Owner-relative, as in Notify... above (0x489db2 reloads the converted stack local).
  currentPoint = ownerRelativePoint;
  capturedControl->DispatchPictureResourceCommand(2, &startPoint, &lastPoint, &currentPoint, 1);
  capturedControl = 0;
}

// Copies the global mouse-capture state's latest tracked point into the caller's buffer.
// FUNCTION: IMPERIALISM 0x00489e40
void __cdecl RenderMapOrderEntryTilePreview_Impl(CPoint* out) {
  // Loads both members then stores both, matching the original's POD point copy.
  LONG y = g_McAppMouseCaptureState.currentPoint.y;
  LONG x = g_McAppMouseCaptureState.currentPoint.x;
  out->x = x;
  out->y = y;
}
