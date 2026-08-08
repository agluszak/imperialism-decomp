#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064ddc0
class TSwapperDaddyView : public TView {
public:
  DECLARE_DYNCREATE(TSwapperDaddyView)
  virtual ~TSwapperDaddyView() override; // slot 0x01 (scalar deleting destructor)

  // NOOP: verified empty in original 0x004ac5f5 (no standalone TSwapperDaddyView::TSwapperDaddyView body exists: CreateObject 0x004ac5c0 inlines this default ctor, calling the TView base ctor directly at that site)
  TSwapperDaddyView() {}

  // Selects the child control whose controlTag matches `tag`: lays the match at the origin
  // (visible) and every other child off-screen at (1000,1000), caches the tag, and returns
  // the matched child. If the tag is already the cached one, forwards to ResolveControlByTag.
  TView* SelectSwapperItemByTag(int tag); // 0x004ac6c0

  int selectedTag60; // 0x60 — currently displayed child's controlTag
};
ASSERT_SIZE(TSwapperDaddyView, 0x64);
