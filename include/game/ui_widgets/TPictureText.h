#pragma once

#include "game/ui_core/TStaticText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066c990
class TPictureText : public TStaticText {
public:
  DECLARE_DYNCREATE(TPictureText)
  virtual ~TPictureText() override; // slot 0x01 (scalar deleting destructor)

  TPictureText();
};
