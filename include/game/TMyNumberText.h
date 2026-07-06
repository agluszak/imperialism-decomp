#pragma once

#include "game/TNumberText.h"

// Numeric text control variant: same 0xac layout as TNumberText (adds no fields);
// overrides the cached-int refresh to pull the value through the shared-string helper.
// RTTI: classTMyNumberText @ 0x0066c3a8, base TNumberText.
// VTABLE: IMPERIALISM 0x0066c4f0
class TMyNumberText : public TNumberText {
public:
  DECLARE_DYNCREATE(TMyNumberText)

  TMyNumberText();
  virtual ~TMyNumberText(); // slot 0x01 (scalar deleting destructor 0x5b5000)

  int UpdateControlCachedIntFromWindowText() override; // slot 0x7a 0x5b5050
};

ASSERT_SIZE(TMyNumberText, 0xac);
