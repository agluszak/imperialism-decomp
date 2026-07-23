#pragma once

#include "game/ui_widgets/TInfoBarText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066d288
class TInfoBarPictureText : public TInfoBarText {
public:
  DECLARE_DYNCREATE(TInfoBarPictureText)
  virtual ~TInfoBarPictureText() override;           // slot 0x01 (scalar deleting destructor)
  virtual void ClearTextAndLayoutRect(int) override; // slot 0x7f 0x5b5dd0
  virtual void SetTextAndLayoutRect(CString text,
                                    RECT* layoutRect) override; // slot 0x80 0x5b5cb0

  TInfoBarPictureText();
};
