#pragma once

#include "compat.h"

#include "game/ui_core/TStaticText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00662640
class TSelectoText : public TStaticText {
public:
  DECLARE_DYNCREATE(TSelectoText)
  virtual ~TSelectoText() override; // slot 0x01 (scalar deleting destructor)
  virtual void Hilite();            // slot 0x76 0x57b760; Mac symbol oracle

  // NOOP: verified empty in original 0x0057b6a6 (no standalone TSelectoText::TSelectoText body exists: CreateObject 0x0057b670 inlines this default ctor, calling the TStaticText base ctor directly at that site)
  TSelectoText() {}
};
ASSERT_SIZE(TSelectoText, 0x94);
