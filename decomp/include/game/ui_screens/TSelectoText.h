#pragma once

#include "compat.h"

#include "game/ui_core/TStaticText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00662640
class TSelectoText : public TStaticText {
public:
  DECLARE_DYNCREATE(TSelectoText)
  virtual ~TSelectoText() override;
  virtual void Hilite(); // Mac symbol oracle

  // NOOP: verified empty in original 0x0057b6a6
  TSelectoText() {}
};
ASSERT_SIZE(TSelectoText, 0x94);
