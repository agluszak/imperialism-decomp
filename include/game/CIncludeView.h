#pragma once

#include "game/CDib.h"
#include "game/mfc.h"

class TView;

// MFC view class for the SDI doc template (CRuntimeClass @ 0x006481c8, m_lpszClassName
// CIncludeView, m_nObjectSize 0x94). Not TIncludeView @ 0x6495d0 (game UI hierarchy).
//
// This is the real receiver of ImperialismApp::InitInstance's post-startup hookup: it is
// CFrameWnd::m_pViewActive for the SDI main frame, so it is what
// GetMainViewHostFromActiveThread() (0x00412a70) actually returns — not a TView.
class CIncludeView : public CView {
public:
  DECLARE_DYNCREATE(CIncludeView)

  CIncludeView();

  void SetUiRuntimeContextAndActivateMain(TView* activeDialog); // 0x00483340

protected:
  void OnDraw(CDC* pDC) override;

  TView* m_activeDialogContext; // 0x40
  unsigned char pad44[0x94 - 0x44];
};

ASSERT_SIZE(CIncludeView, 0x94);
