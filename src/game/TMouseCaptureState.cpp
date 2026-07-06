#include "game/TMouseCaptureState.h"

#include "game/TControl.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x00489cb0
void TMouseCaptureState::NotifyCaptureOwnerState1AndMaybeUpdateCoords(unsigned int nFlags, int x,
                                                                      int y) {
  if (capturedControl == 0) {
    return;
  }
  CPoint ownerRelativePoint(x, y);
  capturedControl->SubtractPosAndDispatchToOwnerSlot19C(&ownerRelativePoint);
  lastPoint = currentPoint;
  // Ground truth gates this on bit 0x20 of nFlags (MK_XBUTTON1 in the standard WM_MOUSEMOVE
  // flag set); the exact intent of skipping the coordinate update on that bit isn't recovered.
  if ((nFlags & 0x20) == 0) {
    currentPoint.x = x;
    currentPoint.y = y;
  }
  // Ground truth pushes a trailing "1" flag arg the declared 4-param
  // DispatchPictureResourceCommand signature doesn't model (same arity caveat as
  // TControl::BeginMouseCaptureAndStartRepeatTimer's call and the note in
  // TMapUberPicture.h/.cpp).
  capturedControl->DispatchPictureResourceCommand(1, &startPoint, &lastPoint, &currentPoint);
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
  capturedControl->SubtractPosAndDispatchToOwnerSlot19C(&ownerRelativePoint);
  lastPoint = currentPoint;
  currentPoint.x = x;
  currentPoint.y = y;
  capturedControl->DispatchPictureResourceCommand(2, &startPoint, &lastPoint, &currentPoint);
  capturedControl = 0;
}
