#include "game/ui_core/CMcEditWindow.h"

#include "game/ui_core/CIncludeView.h"
#include "game/ImperialismApp.h"

#ifndef IMPERIALISM_LINT
BEGIN_MESSAGE_MAP(CMcEditWindow, CEdit)
ON_WM_CHAR()
END_MESSAGE_MAP()
#endif

// FUNCTION: IMPERIALISM 0x00489e70
void CMcEditWindow::OnChar(UINT nChar, UINT nRepCnt, UINT nFlags) {
  if (nChar == 0x0a || nChar == 0x0d || nChar == 0x1b) {
    if (GetMainViewHostFromActiveThread() != 0) {
      HWND hostWindow = GetMainViewHostFromActiveThread()->m_hWnd;
      ::SendMessageA(hostWindow, WM_KEYDOWN, nChar, 0);
    }
  }
  CWnd::OnChar(nChar, nRepCnt, nFlags);
}
