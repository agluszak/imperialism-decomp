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
// VTABLE: IMPERIALISM 0x0064b7c8
class CMcWindow : public CWnd {
public:
  DECLARE_DYNCREATE(CMcWindow) // GetRuntimeClass slot 0x00; classCMcWindow @ 0x0064b5d0
  // Construct the host window for a TWindow descriptor and realize/show it (0x00493470):
  // derives the CreateEx window style from the descriptor's type code, then drives the
  // MFC CreateEx/SetWindowPos/BringWindowToTop window-creation surface.
  explicit CMcWindow(TWindow* descriptor = NULL);
  // Detaches the owning TWindow (slot 0x74 CloseAndFree) before the CWnd base is torn down.
  virtual ~CMcWindow() override; // 0x00493760 (scalar deleting destructor 0x00493730)

  // Overrides CWnd::PreCreateWindow (vtable slot 0x64): register a private "AmbitMcWindow"
  // WNDCLASS (CS_HREDRAW|CS_VREDRAW, DefWindowProc, module instance) and force cs.lpszClass
  // before delegating to CWnd::PreCreateWindow.
  BOOL PreCreateWindow(CREATESTRUCT& cs) override; // 0x00493d80
  // Overrides CWnd::OnCommand (vtable slot 0x80): for custom notify code 0x400 (HIWORD of
  // wParam), refresh the sending control's owning TView (RefreshControl, slot 0x39) and
  // re-arm the owner tree's input capture (ForceRedraw, slot 0x4f), then default-route.
  BOOL OnCommand(WPARAM wParam, LPARAM lParam) override; // 0x00493c30

  // +0x3c — backref to the owning TWindow, installed by
  // CreateMcWindowFromDescriptorAndShow and cleared during TWindow::Free. Sits
  // immediately after the CWnd subobject (CWnd ends at +0x3c in this build).
  TWindow* m_pOwnerWindow;

  // Message handlers (original message map: 14 entries, AFX_MSGMAP_ENTRY table at
  // 0x0064b5f0, AFX_MSGMAP at 0x0064b5e8 chaining to CWnd's at 0x670868). Still
  // unported: WM_CTLCOLOR (0x493b70) — needs the
  // module-library-cache color methods (0x4995c0 arg shape, 0x49ace0, 0x47e930);
  // WM_CHAR (0x493ce0) — function-static object of the 0x14-byte class with vtable
  // 0x648590 (ctor 0x4845a0) + cleanup registration; and message 0x36a (0x493d50) —
  // dispatches slot 0x1a on the unidentified global object at 0x6a1348.

  // 0x468 — window-state command sent by TWindow (Open
  // sends wParam=0, Close sends wParam=1 — both no-ops here; 2=show,
  // 3=hide, 4=destroy-and-delete-self).
  afx_msg LRESULT OnWindowStateMsg468(WPARAM wParam, LPARAM lParam);
  // WM_PAINT — the real trigger for all TView-tree painting: builds a CPaintDC and
  // dispatches m_pOwnerWindow->PaintVisibleChildrenIntersectingClipRect (TView slot
  // 0x43) with the paint DC.
  afx_msg void OnPaint();
  afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
  // WM_LBUTTONUP — completes a click: forwards to the owner tree's slot-0x48 mouse-up
  // dispatch, then ends the global mouse capture (g_McAppMouseCaptureState).
  afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
  // WM_MOUSEMOVE — updates the capture drag state, routes the cursor to the UI root
  // controller, then (when the app is active) runs the owner tree's hover hit-test.
  afx_msg void OnMouseMove(UINT nFlags, CPoint point);
  afx_msg void OnClose();
  afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
  afx_msg void OnKeyUp(UINT nChar, UINT nRepCnt, UINT nFlags);
  afx_msg BOOL OnQueryNewPalette();
  afx_msg void OnPaletteChanged(CWnd* pFocusWnd);

  DECLARE_MESSAGE_MAP()
};
