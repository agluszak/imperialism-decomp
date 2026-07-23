#pragma once

#include "game/ui_widgets/TDeluxeText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063eb00
class TInfoBarText : public TDeluxeText {
public:
  DECLARE_DYNCREATE(TInfoBarText)
  virtual ~TInfoBarText() override;         // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;             // slot 0x07 0x5b6930
  virtual void ClearTextAndLayoutRect(int); // slot 0x7f 0x5b6770
  virtual void SetTextAndLayoutRect(CString text, RECT* layoutRect); // slot 0x80 0x5b66b0
  virtual void InitializeMapHintTextStyleAndThemeFlags(int stylePrimary,
                                                       int styleSecondary); // slot 0x81 0x5b6840
  // Applies the default map-hint style pair (0x2b6c/0x2b67) through slot 0x81.
  virtual void ApplyDefaultMapHintTextStyle(); // slot 0x82 0x5b6810

  RECT layoutRectA4; // +0xa4

  TInfoBarText();
};
