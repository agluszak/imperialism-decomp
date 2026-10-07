#pragma once

#include "compat.h"

#include "game/military_ui/TCheater.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064ee58
class TTechCheater : public TCheater {
public:
  DECLARE_DYNCREATE(TTechCheater)
  virtual ~TTechCheater() override;
  void ApplyCheats() override; // Mac symbol oracle

  void ITechCheater(TView* panel);

  // NOOP: verified empty in original 0x004b18b3
  TTechCheater() {}
};
ASSERT_SIZE(TTechCheater, 0x64);
