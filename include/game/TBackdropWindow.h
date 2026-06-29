#pragma once

#include "game/CDib.h"
#include "game/mfc.h"

// Temporary loading/backdrop CWnd subclass created during CMainFrame::OnCreate.
// It is a CWnd-sized object plus one cached bitmap handle at +0x3c.
//
// Retail vftable 0x0064bca8; not annotated with // VTABLE because the current
// linked MFC headers emit extra OLE/dispatch slots, as with CMainFrame.
class TBackdropWindow : public CWnd {
public:
  TBackdropWindow();
  virtual ~TBackdropWindow();

  void InitializeDefaultBackdropWindowFromBmp3B6(CWnd* parent);
  void ResetTopLevelWindowStateAndReleaseTempMapBuffer();

  CDib* m_backdropBmp; // 0x3c
};

ASSERT_SIZE(TBackdropWindow, 0x40);

void CreateGlobalBackdropWindowWithDefaultBmp3B6(CWnd* parent);
void RefreshBackdropOnInputMessages(MSG* msg);
