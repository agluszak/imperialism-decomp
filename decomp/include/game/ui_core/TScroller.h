#pragma once

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"

// VTABLE: IMPERIALISM 0x00649a68
class TScroller : public TView {
public:
  DECLARE_DYNCREATE(TScroller)

  TScroller() {}

  virtual ~TScroller() override;

  void InitializeScrollerPlacement(TView* owner, int* offsetLayout, int* sizeLayout);
};

ASSERT_SIZE(TScroller, 0x60);
