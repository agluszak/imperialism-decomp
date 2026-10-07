#pragma once

#include "game/gfx/CDib.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064bca8
class TBackdropWindow : public CWnd {
  DECLARE_MESSAGE_MAP()

public:
  TBackdropWindow();

  virtual ~TBackdropWindow() override;

  void InitializeBackdrop(CWnd* parent);
  void DestroyAndRefreshMainWindow();
  virtual void PostNcDestroy() override;

  CDib* m_backdropBmp;

protected:
  afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
  afx_msg void OnPaint();
  afx_msg void OnTimer(UINT timerId);
};

ASSERT_SIZE(TBackdropWindow, 0x40);

// Guarded creator @ 0x0049cc60 — see g_cachedShowSplashFlag in global_data_tables.h.
void CreateBackdropWindowIfSplashEnabled(CWnd* parent);
void RefreshBackdropOnInputMessages(MSG* msg);
