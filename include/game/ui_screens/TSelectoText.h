#pragma once

#include "game/ui_core/TStaticText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00662640
class TSelectoText : public TStaticText {
public:
  DECLARE_DYNCREATE(TSelectoText)
  virtual ~TSelectoText() override; // slot 0x01 (scalar deleting destructor)
  virtual void Hilite();            // slot 0x76 0x57b760; Mac symbol oracle

  TSelectoText();
};
