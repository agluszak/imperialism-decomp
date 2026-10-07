#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064ddc0
class TSwapperDaddyView : public TView {
public:
  DECLARE_DYNCREATE(TSwapperDaddyView)
  virtual ~TSwapperDaddyView() override; // slot 0x01 (scalar deleting destructor)

  // NOOP: verified empty in original 0x004ac5f5
  TSwapperDaddyView() {}

  TView* SelectSwapperItemByTag(int tag); // 0x004ac6c0

  int selectedTag; // 0x60 — currently displayed child's controlTag
};
ASSERT_SIZE(TSwapperDaddyView, 0x64);
