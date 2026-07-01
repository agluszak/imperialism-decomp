#include "game/CMcWindow.h"

#include "game/TWindow.h"

IMPLEMENT_DYNCREATE(CMcWindow, CWnd)

// Build the host window for a TWindow descriptor: construct the CWnd base, record the
// owner backref, derive the CreateEx window style from the descriptor's type code, then
// create and bring up the window via the real MFC CWnd surface. (The original also fires
// one-shot debug asserts for unrecognized type codes; those validation-only calls are
// omitted here.)
// FUNCTION: IMPERIALISM 0x00493470
CMcWindow::CMcWindow(TWindow* descriptor) : CWnd() {
  m_pOwnerWindow = descriptor;

  DWORD dwExStyle = 0;
  DWORD dwStyle = (descriptor->windowStyleType != 0) ? 0x44020000 : 0x44000000;
  int typeCode = static_cast<int>(descriptor->windowStyleType) & ~0x8;
  switch (typeCode) {
  case 0x00:
    dwStyle |= 0x00fc0000;
    dwExStyle = 0x80;
    break;
  case 0x01:
    dwStyle |= 0x00400000;
    break;
  case 0x02:
    break;
  case 0x03:
    dwStyle |= 0x00800000;
    break;
  case 0x04:
    dwStyle |= 0x00c80000;
    dwExStyle = 0x80;
    break;
  case 0x05:
    dwStyle |= 0x00cc0000;
    break;
  case 0x30:
  case 0x1f40:
    dwExStyle = 0x80;
    if (descriptor->field6d == 0) {
      dwStyle |= 0x80c00000;
    } else {
      dwStyle |= 0x00c80000;
    }
    break;
  default:
    // Other type codes (0x10, 0x7c3, ...) add no style bits; the original only
    // validates them with debug asserts.
    break;
  }
  if (descriptor->field70 != 0) {
    dwExStyle |= 0x8; // WS_EX_TOPMOST
  }

  CRect rect;
  rect.left = descriptor->ownerOffsetX;
  rect.top = descriptor->ownerOffsetY;
  rect.right = rect.left + descriptor->field34;
  rect.bottom = rect.top + descriptor->field38;
  ::AdjustWindowRectEx(&rect, dwStyle, FALSE, dwExStyle);

  CWnd* mainWnd = AfxGetMainWnd();
  HWND parent = (mainWnd != NULL) ? mainWnd->m_hWnd : NULL;
  CreateEx(dwExStyle, NULL, NULL, dwStyle, rect.left, rect.top, rect.Width(), rect.Height(), parent,
           NULL, NULL);
  SetWindowPos(&CWnd::wndTop, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
  BringWindowToTop();
}
