#pragma once

#include "game/TModalDialogBase.h"
#include "game/mfc.h"

// Template FB dual-text modal dialog (own vtable 0x646958). A CDialog subclass (via
// TModalDialogBase) with two embedded CWnd child controls at +0x74 / +0xb0 and a check
// state at +0xec.
class TAutoResolutionDialog : public TModalDialogBase {
public:
  explicit TAutoResolutionDialog(void* initParam = nullptr); // 0x0047dfd0

  BOOL UpdateData(BOOL saveAndValidate); // 0x0047e0c0

  int DialogResult() const {
    return reinterpret_cast<const int*>(this)[0x2c / 4];
  }

  CWnd primaryDialogControl;    // 0x74
  CWnd secondaryDialogControl;  // 0xb0
  int autoResolutionCheckState; // 0xec
};
