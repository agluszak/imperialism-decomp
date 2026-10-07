#pragma once

#include "compat.h"

#include "game/ui_widgets/TInfoBarText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066d288
class TInfoBarPictureText : public TInfoBarText {
public:
  DECLARE_DYNCREATE(TInfoBarPictureText)
  virtual ~TInfoBarPictureText() override;
  virtual void ClearTextAndLayoutRect(int) override;
  virtual void HotText(CString text, RECT* layoutRect) override;

  TInfoBarPictureText() {}
};
ASSERT_SIZE(TInfoBarPictureText, 0xb4);
