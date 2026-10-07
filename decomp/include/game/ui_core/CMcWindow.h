#pragma once

#include "compat.h"

#include "game/mfc.h"

class TWindow;

// VTABLE: IMPERIALISM 0x0064b7c8
class CMcWindow : public CWnd {
public:
  DECLARE_DYNCREATE(CMcWindow) // GetRuntimeClass slot 0x00; classCMcWindow @ 0x0064b5d0
  explicit CMcWindow(TWindow* descriptor = NULL);
  // Detaches the owning TWindow (slot 0x74 CloseAndFree) before the CWnd base is torn down.
  virtual ~CMcWindow() override; // 0x00493760 (scalar deleting destructor 0x00493730)

  BOOL PreCreateWindow(CREATESTRUCT& cs) override;       // 0x00493d80
  BOOL OnCommand(WPARAM wParam, LPARAM lParam) override; // 0x00493c30

  TWindow* m_pOwnerWindow;

  // Message handlers (13-entry message map).

  afx_msg LRESULT OnWindowStateMsg468(WPARAM wParam, LPARAM lParam);
  afx_msg void OnPaint();
  afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
  afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
  afx_msg void OnMouseMove(UINT nFlags, CPoint point);
  afx_msg void OnClose();
  afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
  afx_msg void OnKeyUp(UINT nChar, UINT nRepCnt, UINT nFlags);
  afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor); // 0x00493b70
  afx_msg BOOL OnQueryNewPalette();
  afx_msg void OnPaletteChanged(CWnd* pFocusWnd);
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags); // 0x00493ce0
  // MFC idle-update message: forward lParam to the application OnIdle override.
  afx_msg LRESULT OnIdleUpdateMsg36A(WPARAM wParam, LPARAM lParam); // 0x00493d50

  DECLARE_MESSAGE_MAP()
};
ASSERT_SIZE(CMcWindow, 0x40);
