#pragma once

#include "compat.h"

#include "game/ui_widgets/TDeluxeText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063eb00
class TInfoBarText : public TDeluxeText {
public:
  DECLARE_DYNCREATE(TInfoBarText)
  virtual ~TInfoBarText() override;
  virtual void Free() override;
  virtual void ClearTextAndLayoutRect(int);
  virtual void HotText(CString text, RECT* layoutRect);
  virtual void InitializeMapHintTextStyleAndThemeFlags(short stylePrimary, int styleSecondary);
  // Applies the default map-hint style pair (0x2b6c/0x2b67) through slot 0x81.
  virtual void Reset();

  RECT layoutRect;

  TInfoBarText();
};
ASSERT_SIZE(TInfoBarText, 0xb4);
