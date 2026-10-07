#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064ddc0
class TSwapperDaddyView : public TView {
public:
  DECLARE_DYNCREATE(TSwapperDaddyView)
  virtual ~TSwapperDaddyView() override;

  // NOOP: verified empty in original 0x004ac5f5
  TSwapperDaddyView() {}

  TView* SelectSwapperItemByTag(int tag);

  int selectedTag; // currently displayed child's controlTag
};
ASSERT_SIZE(TSwapperDaddyView, 0x64);
