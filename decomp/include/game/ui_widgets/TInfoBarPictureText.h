#pragma once

#include "compat.h"

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

  // NOOP: verified empty in original 0x005b5af7; TDeluxeText's ctor performs the
  // field init seen inline at CreateObject 0x005b5ac0. The standalone emission at
  // 0x005b5bd0 is this ctor's retained COMDAT (base zeroing inlined, derived vptr
  // 0x66d288 stored last).
  // SYNTHETIC: IMPERIALISM 0x005b5bd0
  // TInfoBarPictureText::TInfoBarPictureText
  TInfoBarPictureText() {}
};
ASSERT_SIZE(TInfoBarPictureText, 0xb4);
