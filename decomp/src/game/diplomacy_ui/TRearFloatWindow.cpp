#include "game/diplomacy_ui/TRearFloatWindow.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TRearFloatWindow, TFloatWindow)

// FUNCTION: IMPERIALISM 0x004f38e0
TRearFloatWindow::TRearFloatWindow() {
  // Base constructor TFloatWindow() handles registration and setup.
}

// FUNCTION: IMPERIALISM 0x004f3960
bool TRearFloatWindow::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  short partCode = ContainsMouse(point);
  switch (partCode) {
  case 3:
    return TFloatWindow::HandleMouseDown(point, event, origin);
  case 4:
    MoveByUser(point);
    return true;
  case 5:
    ResizeByUser(point);
    return true;
  case 6:
    GoAwayByUser(point);
    return true;
  case 7:
  case 8:
    ZoomByUser(point, partCode);
    return true;
  }
  return true;
}
