#pragma once

#include "game/ui_widgets/TPictureNumberText.h"

// VTABLE: IMPERIALISM 0x0066d038
class TDropShadowNumberText : public TPictureNumberText {
public:
  DECLARE_DYNCREATE(TDropShadowNumberText)

  TDropShadowNumberText();
  virtual ~TDropShadowNumberText() override;

  void Draw(RECT* rectBuffer) override;

  COLORREF shadowColor; // quickdraw color used for the shadow pass
};

ASSERT_SIZE(TDropShadowNumberText, 0xb0);
