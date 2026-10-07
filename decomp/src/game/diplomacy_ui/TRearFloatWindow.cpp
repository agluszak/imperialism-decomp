#include "game/diplomacy_ui/TRearFloatWindow.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TRearFloatWindow, TFloatWindow)

// FUNCTION: IMPERIALISM 0x004f38e0
TRearFloatWindow::TRearFloatWindow() : TFloatWindow() {
  // Base constructor TFloatWindow() handles registration and setup.
}

// Destructors are compiler-generated (implicit) from real inheritance.
// No own destructor: the original's 0x004f3940 is an ILT thunk to the base's
// ~TWindow (0x0048d670), so this class inherits it. The scalar deleting destructor above is what
// the vtable slot holds.

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
