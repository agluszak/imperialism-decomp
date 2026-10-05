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
  virtual ~TScrollView() override;             // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x573ce0
  virtual void
  PaintVisibleChildrenIntersectingClipRect(RECT* clipRect,
                                           CDC* paintDc) override; // slot 0x43 0x5742b0

  TView* contentView;        // 0x60 — the scrolled content view
  TScrollBarView* scrollBar; // 0x64 — companion scrollbar control

  TScrollView() {}

  void IScrollView(TView* panel, int* offsetLayout, int* sizeLayout);
  void Reset();
  void ScrollOnce(int direction);
  void ScrollPage(int direction);
  void ScrollRelative(short horizontalDelta, short verticalDelta);
  void ScrollToPercent(int percent); // 0x574160
};
ASSERT_SIZE(TScrollView, 0x68);
