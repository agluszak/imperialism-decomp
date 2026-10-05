#pragma once

#include "game/ui_core/TNumberText.h"

// VTABLE: IMPERIALISM 0x0066c4f0
class TMyNumberText : public TNumberText {
public:
  DECLARE_DYNCREATE(TMyNumberText)

  TMyNumberText();

  int UpdateControlCachedIntFromWindowText() override; // slot 0x7a 0x5b5050
};

ASSERT_SIZE(TMyNumberText, 0xac);
