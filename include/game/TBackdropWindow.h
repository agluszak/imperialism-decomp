#pragma once

#include "game/CDib.h"
#include "game/mfc.h"

// Temporary loading/backdrop CWnd subclass created during CMainFrame::OnCreate.
// It is a CWnd-sized object plus one cached bitmap handle at +0x3c.
//
// Retail vftable 0x0064bca8; not annotated with // VTABLE because the current
// linked MFC headers emit extra OLE/dispatch slots, as with CMainFrame.
class TBackdropWindow : public CWnd {
  DECLARE_MESSAGE_MAP()

public:
  TBackdropWindow();
  virtual ~TBackdropWindow() override;

  void InitializeDefaultBackdropWindowFromBmp3B6(CWnd* parent);
  virtual void PostNcDestroy() override;

  CDib* m_backdropBmp; // 0x3c

protected:
  afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
  afx_msg void OnPaint();
  afx_msg void OnTimer(UINT timerId);
};

ASSERT_SIZE(TBackdropWindow, 0x40);

// Guarded creator @ 0x0049cc60 — see g_cachedShowSplashFlag in global_data_tables.h.
void WrapperFor_AllocateWithFallbackHandler_At0049cc60(CWnd* parent);
void CreateGlobalBackdropWindowWithDefaultBmp3B6(TBackdropWindow* window, CWnd* parent);
void RefreshBackdropOnInputMessages(MSG* msg);
