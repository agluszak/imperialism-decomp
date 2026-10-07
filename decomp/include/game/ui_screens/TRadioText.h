#pragma once

#include "game/ui_widgets/TDropShadowText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642b18
class TRadioText : public TDropShadowText {
public:
  DECLARE_DYNCREATE(TRadioText)
  virtual ~TRadioText() override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void Hilite();

  TRadioText();

  bool isSelectedOption;
  unsigned char pad99[3]; // not read/written by SetSelectedTextOptionByTag
};
ASSERT_SIZE(TRadioText, 0x9c);
