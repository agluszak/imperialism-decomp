#pragma once

#include "game/ui_widgets/TDropShadowText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642b18
class TRadioText : public TDropShadowText {
public:
  DECLARE_DYNCREATE(TRadioText)
  virtual ~TRadioText() override;               // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x579490
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5794b0
  virtual void Hilite(); // slot 0x76 0x579580

  TRadioText();

  bool isSelectedOption;
  unsigned char pad99[3]; // 0x99 — not read/written by SetSelectedTextOptionByTag
};
ASSERT_SIZE(TRadioText, 0x9c);
