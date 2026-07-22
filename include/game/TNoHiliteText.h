#pragma once

#include "game/TStaticText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066d500
class TNoHiliteText : public TStaticText {
public:
  DECLARE_DYNCREATE(TNoHiliteText)
  virtual ~TNoHiliteText() override; // slot 0x01 (scalar deleting destructor)

  TNoHiliteText();
};
