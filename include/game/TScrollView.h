#pragma once

#include "game/TView.h"
#include "game/mfc.h"
#include "game/ui_tags_common.h"

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

  // Layout past TView (0x60): allocation size 0x68 (`new` at 0x5d60d5), the slot-0x37
  // builder (0x573ce0) stores the 'scro'-tagged content view at +0x60 and the freshly
  // built TScrollBarView at +0x64.
  TView* contentView60;        // 0x60 — the scrolled content view
  TScrollBarView* scrollBar64; // 0x64 — companion scrollbar control

  // Inline in the original: callsites (0x5d60ee) expand this to the TView base ctor +
  // vptr store with no field init, so the body must stay empty and in the header.
  // NOOP: verified empty in original 0x005d60ee
  TScrollView() {}

  // 0x00573cb0 — forward to InitializeUiResourceEntryFrameAndParent with the fixed
  // (5, 5) layout margins and no attach.
  void InitializeScrollView(TView* panel, int* offsetLayout, int* sizeLayout);
  // 0x005741e0 — re-capture the content view's layout, clamp the scrollbar's word8c
  // to min(word88, word8a), and enable/disable the bar by content overflow.
  void SyncBoundedValueAndToggleControlStates();
  // 0x00573f60 — shift the content view's origin by (mode, delta), clamp to the
  // scrollable range, re-layout the content, and re-derive scrollBar64's word8c
  // track position from the new offset.
  void AdjustCityDialogScrollRangeByDeltaAndClamp(short mode, short delta);
};
