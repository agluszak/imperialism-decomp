#pragma once

#include "game/ui_widgets/TPictureText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066ce00
class TDropShadowText : public TPictureText {
public:
  DECLARE_DYNCREATE(TDropShadowText)
  virtual ~TDropShadowText() override;
  virtual void Draw(RECT* rectBuffer) override;

  TDropShadowText();

  COLORREF shadowColor; // resolved QuickDraw shadow color
};
ASSERT_SIZE(TDropShadowText, 0x98);
