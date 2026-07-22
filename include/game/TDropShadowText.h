#pragma once

#include "game/TPictureText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066ce00
class TDropShadowText : public TPictureText {
public:
  DECLARE_DYNCREATE(TDropShadowText)
  virtual ~TDropShadowText() override;          // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5b5650

  TDropShadowText();

  COLORREF shadowColor94; // +0x94 -- resolved QuickDraw shadow color
};
ASSERT_SIZE(TDropShadowText, 0x98);
