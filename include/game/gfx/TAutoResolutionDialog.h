#pragma once

#include "game/gfx/TModalDialogBase.h"
#include "game/mfc.h"

// Template FB dual-text modal dialog (own vtable 0x646958). A CDialog subclass (via
// TModalDialogBase) with two embedded CWnd child controls at +0x74 / +0xb0 and a check
// state at +0xec.
// VTABLE: IMPERIALISM 0x00646958
class TAutoResolutionDialog : public TModalDialogBase {
public:
  explicit TAutoResolutionDialog(void* initParam = nullptr); // 0x0047dfd0
  ~TAutoResolutionDialog() override;                         // 0x004152e0

  int DialogResult() const {
    return m_nModalResult;
  }

  CButton primaryDialogControl;    // 0x74, vtable 0x671c4c
  CListBox secondaryDialogControl; // 0xb0, vtable 0x671d1c
  int autoResolutionCheckState;    // 0xec

protected:
  BOOL OnInitDialog() override;                     // 0x0047e120 (vtable index 49)
  void DoDataExchange(CDataExchange* pDX) override; // 0x0047e0c0 (vtable index 35)
  DECLARE_MESSAGE_MAP()                             // GetMessageMap 0x0047e100 (index 12)
};
