#pragma once

#include "game/mfc.h"

class TWindow;

// CMcWindow — the native host window backing a TView/TWindow. It is a real MFC CWnd
// subclass: it carries its own CRuntimeClass (g_pClassDescCMcWindow), its HWND lives in
// the inherited CWnd::m_hWnd (+0x1c), and CreateMcWindowFromDescriptorAndShow installs
// the CMcWindow vtable (0x0064b7c8) and backrefs the owning TWindow at +0x3c.
//
// The three text/enable helpers below reimplement the corresponding CWnd operations:
// when the inherited control-site pointer (CWnd::m_pCtrlSite, +0x38) is null they drive
// the HWND through the Win32 API, otherwise they let the active control site handle it.
// They are ordinary (non-virtual) thiscall methods invoked directly by address, so this
// class deliberately models no new vtable yet (vtable recovery is separate work).
class CMcWindow : public CWnd {
public:
  DECLARE_DYNCREATE(CMcWindow) // GetRuntimeClass slot 0x00; classCMcWindow @ 0x0064b5d0
  // Construct the host window for a TWindow descriptor and realize/show it (0x00493470):
  // derives the CreateEx window style from the descriptor's type code, then drives the
  // MFC CreateEx/SetWindowPos/BringWindowToTop window-creation surface.
  explicit CMcWindow(TWindow* descriptor = NULL);

  void SetWindowTextOrDelegateToOwner(const char* text); // 0x006073b4
  void GetWindowTextOrDelegateToOwner(CString* out);     // 0x0060859f
  void EnableWindowOrDelegateToOwner(int enable);        // 0x0060753b

  // +0x3c — backref to the owning TWindow, installed by
  // CreateMcWindowFromDescriptorAndShow and cleared during TWindow::Free. Sits
  // immediately after the CWnd subobject (CWnd ends at +0x3c in this build).
  TWindow* m_pOwnerWindow;
};
