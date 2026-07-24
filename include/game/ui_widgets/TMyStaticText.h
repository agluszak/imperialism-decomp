#pragma once

#include "compat.h"

#include "game/ui_core/TStaticText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066cbc8
class TMyStaticText : public TStaticText {
public:
  DECLARE_DYNCREATE(TMyStaticText)
  virtual ~TMyStaticText() override; // slot 0x01 (scalar deleting destructor)

  TMyStaticText();
};
ASSERT_SIZE(TMyStaticText, 0x94);
