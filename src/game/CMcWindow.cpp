#include "game/CMcWindow.h"

// The native host window for a TView/TWindow. These three helpers mirror the matching
// CWnd operations: with no active control site (CWnd::m_pCtrlSite, +0x38) they talk to
// the HWND directly through the Win32 API; otherwise they defer to the control site,
// which MFC's own CWnd member functions already route to.

// FUNCTION: IMPERIALISM 0x006073b4
void CMcWindow::SetWindowTextOrDelegateToOwner(const char* text) {
  if (m_pCtrlSite == NULL) {
    ::SetWindowTextA(m_hWnd, text);
  } else {
    CWnd::SetWindowText(text);
  }
}

// FUNCTION: IMPERIALISM 0x0060753b
void CMcWindow::EnableWindowOrDelegateToOwner(int enable) {
  if (m_pCtrlSite == NULL) {
    ::EnableWindow(m_hWnd, enable);
  } else {
    CWnd::EnableWindow(enable);
  }
}

// FUNCTION: IMPERIALISM 0x0060859f
void CMcWindow::GetWindowTextOrDelegateToOwner(CString* out) {
  // CWnd::GetWindowText already performs the GetWindowTextLength/GetWindowText sequence
  // for the HWND and routes to the control site when one is present.
  CWnd::GetWindowText(*out);
}
