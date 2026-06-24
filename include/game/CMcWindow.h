#pragma once

#include "game/mfc.h"

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
  void SetWindowTextOrDelegateToOwner(const char* text); // 0x006073b4
  void GetWindowTextOrDelegateToOwner(CString* out);     // 0x0060859f
  void EnableWindowOrDelegateToOwner(int enable);        // 0x0060753b
};
