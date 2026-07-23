#include "game/TRearFloatWindow.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x004f3840
// TRearFloatWindow::CreateObject
// SYNTHETIC: IMPERIALISM 0x004f38c0
// TRearFloatWindow::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRearFloatWindow, TFloatWindow)

// FUNCTION: IMPERIALISM 0x004f38e0
TRearFloatWindow::TRearFloatWindow() : TFloatWindow() {
  // Base constructor TFloatWindow() handles registration and setup.
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x004f3910
// TRearFloatWindow::`scalar deleting destructor'
TRearFloatWindow::~TRearFloatWindow() {}

// FUNCTION: IMPERIALISM 0x004f3960
char TRearFloatWindow::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  short partCode = ContainsMouse(point);
  switch (partCode) {
  case 3:
    return TFloatWindow::HandleMouseDown(point, event, origin);
  case 4:
    MoveByUser(point);
    return 1;
  case 5:
    ResizeByUser(point);
    return 1;
  case 6:
    GoAwayByUser(point);
    return 1;
  case 7:
  case 8:
    ZoomByUser(point, partCode);
    return 1;
  }
  return 1;
}
