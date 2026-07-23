#pragma once

#include "compat.h"

#include "game/ui_core/TStaticText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066d500
class TNoHiliteText : public TStaticText {
public:
  DECLARE_DYNCREATE(TNoHiliteText)
  virtual ~TNoHiliteText() override; // slot 0x01 (scalar deleting destructor)

  TNoHiliteText();
};
ASSERT_SIZE(TNoHiliteText, 0x94);
