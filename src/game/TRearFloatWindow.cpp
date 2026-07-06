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
char TRearFloatWindow::DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) {
  int inBounds = TestPointInBounds(point);
  switch (static_cast<short>(inBounds)) {
  case 3:
    return TFloatWindow::DispatchUiMouseMoveToChildren(point, arg2, arg3, arg4);
  case 4:
    ReturnFromUiSlot61(reinterpret_cast<int>(point));
    return 1;
  case 5:
    ReturnFromUiSlot62(reinterpret_cast<int>(point));
    return 1;
  case 6:
    ReturnFromUiSlot60(reinterpret_cast<int>(point));
    return 1;
  case 7:
  case 8:
    ReturnFromUiSlot63(reinterpret_cast<int>(point), inBounds);
    return 1;
  }
  return 1;
}
