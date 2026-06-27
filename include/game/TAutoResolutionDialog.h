#pragma once

#include "game/TControl.h"
#include "game/mfc.h"

// Template FB dual-text modal controller (original stack object 0xf0 bytes, vtable 0x646958).
class TAutoResolutionDialog : public TControlTemplatePrefix {
public:
  explicit TAutoResolutionDialog(void* initParam = nullptr);

  BOOL UpdateData(BOOL saveAndValidate);

  int DialogResult() const { return field2c; }

  CWnd primaryDialogControl;
  CWnd secondaryDialogControl;
  int autoResolutionCheckState;
};
