#pragma once

#include "game/mfc.h"

class TWindow;

// CMcWindow — the native host window backing a TView/TWindow. It is a real MFC CWnd
// subclass: it carries its own CRuntimeClass (g_pClassDescCMcWindow), its HWND lives in
// the inherited CWnd::m_hWnd (+0x1c), and CreateMcWindowFromDescriptorAndShow installs
// the CMcWindow vtable (0x0064b7c8) and backrefs the owning TWindow at +0x3c.
//
// The "text/enable OrDelegateToOwner" helpers that used to live here (0x006073b4,
// 0x0060753b, 0x0060859f) are the real MFC library CWnd::SetWindowText/EnableWindow/
// GetWindowText(CString&) (nafxcw.lib, OCC-support build) — verified against MFC source
// (winocc.cpp): they read the inherited CWnd::m_pCtrlSite directly and are called on
// CIncludeView receivers too, not just CMcWindow. See MfcRuntime.cpp for the
// `// LIBRARY:` markers; callers now use the real inherited CWnd methods directly.
class CMcWindow : public CWnd {
public:
  DECLARE_DYNCREATE(CMcWindow) // GetRuntimeClass slot 0x00; classCMcWindow @ 0x0064b5d0
  // Construct the host window for a TWindow descriptor and realize/show it (0x00493470):
  // derives the CreateEx window style from the descriptor's type code, then drives the
  // MFC CreateEx/SetWindowPos/BringWindowToTop window-creation surface.
  explicit CMcWindow(TWindow* descriptor = NULL);

  // +0x3c — backref to the owning TWindow, installed by
  // CreateMcWindowFromDescriptorAndShow and cleared during TWindow::Free. Sits
  // immediately after the CWnd subobject (CWnd ends at +0x3c in this build).
  TWindow* m_pOwnerWindow;

  // WM_PAINT — the real trigger for all TView-tree painting: builds a CPaintDC and
  // dispatches m_pOwnerWindow->PaintVisibleChildrenIntersectingClipRect (TView slot
  // 0x43) with the paint DC. Original message map (14 entries, AFX_MSGMAP_ENTRY table
  // at 0x0064b5f0, AFX_MSGMAP at 0x0064b5e8 chaining to CWnd's); the remaining 13
  // handlers (mouse/key/palette/0x468/0x36a) are not yet ported.
  afx_msg void OnPaint();

  DECLARE_MESSAGE_MAP()
};
