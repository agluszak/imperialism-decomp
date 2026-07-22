#pragma once

#include "game/TPictureNumberText.h"

// Numeric text control that paints a drop shadow behind the value text. Adds the shadow
// color at +0xac (seeded from the global default). RTTI: classTDropShadowNumberText @
// 0x0066c420, base TPictureNumberText.
// VTABLE: IMPERIALISM 0x0066d038
class TDropShadowNumberText : public TPictureNumberText {
public:
  DECLARE_DYNCREATE(TDropShadowNumberText)

  TDropShadowNumberText();
  virtual ~TDropShadowNumberText() override; // slot 0x01 (scalar deleting destructor 0x5b5960)

  void Draw(RECT* rectBuffer) override; // slot 0x44 0x5b59b0

  COLORREF shadowColorAc; // +0xac — quickdraw color used for the shadow pass
};

ASSERT_SIZE(TDropShadowNumberText, 0xb0);
