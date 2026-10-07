#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

class TScrollBarView;

// VTABLE: IMPERIALISM 0x006417e0
class TScrollView : public TView {
public:
  DECLARE_DYNCREATE(TScrollView)
  virtual ~TScrollView() override;
  virtual void DoPostCreate(int arg) override;
  virtual void PaintChildren(RECT* clipRect, CDC* paintDc) override;

  TView* contentView;        // the scrolled content view
  TScrollBarView* scrollBar; // companion scrollbar control

  // NOOP: verified empty in original 0x005d60ee
  TScrollView() {}

  void IScrollView(TView* panel, int* offsetLayout, int* sizeLayout);
  void Reset();
  void ScrollOnce(int direction);
  void ScrollPage(int direction);
  void ScrollRelative(short horizontalDelta, short verticalDelta);
  void ScrollToPercent(int percent);
};
ASSERT_SIZE(TScrollView, 0x68);
