#include "RuntimeUiDriver.h"

#include "game/ImperialismApp.h"
#include "game/ui_core/CIncludeView.h"
#include "game/ui_core/CMcEditWindow.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TWindow.h"
#include "game/mfc.h"
#include <windows.h>

bool RuntimeUiDriver::ClickViewThroughNativeMessages(TView* view) {
  if (view == 0) {
    return false;
  }
  return ClickViewPointThroughNativeMessages(view, view->frameWidth34 / 2, view->frameHeight38 / 2);
}

bool RuntimeUiDriver::ClickViewPointThroughNativeMessages(TView* view, int localX, int localY) {
  CIncludeView* host = GetMainViewHostFromActiveThread();
  if (view == 0 || host == 0 || host->m_hWnd == 0) {
    return false;
  }

  CPoint position;
  view->GetAbsolutePosition(&position);
  position.x += localX;
  position.y += localY;
  LPARAM mousePosition = MAKELPARAM(position.x, position.y);
  SendMessageA(host->m_hWnd, WM_LBUTTONDOWN, MK_LBUTTON, mousePosition);
  SendMessageA(host->m_hWnd, WM_LBUTTONUP, 0, mousePosition);
  return true;
}

TView* RuntimeUiDriver::FindControl(TView* root, int tag) {
  return root != 0 ? root->ResolveControlByTag(tag) : 0;
}

bool RuntimeUiDriver::ActivateControlSemantically(TView* root, int tag) {
  TControl* control = static_cast<TControl*>(FindControl(root, tag));
  if (control == 0) {
    return false;
  }
  control->HandleEvent(control->GetEventNumber(), control, 0);
  return true;
}

bool RuntimeUiDriver::ClickControlThroughNativeMessages(TView* root, int tag) {
  return ClickViewThroughNativeMessages(FindControl(root, tag));
}
