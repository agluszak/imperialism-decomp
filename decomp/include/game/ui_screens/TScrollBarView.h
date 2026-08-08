#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/ui_tags_screens.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006614c8
class TScrollBarView : public TControl {
public:
  DECLARE_DYNCREATE(TScrollBarView)
  virtual ~TScrollBarView() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;       // slot 0x07 0x5746e0
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005747c0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x574720
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x574970
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x574830
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint,
                          unsigned char commandFlag) override; // slot 0x68 0x574d10

  // Layout past TControl (0x84): allocation size 0x94 (`new` at 0x573d15). The three
  // words at 0x88..0x8c are the bounded-value triple seeded by
  // InitializeScrollBar / the slot-0x37 hook (18 / height-36 / 18) and
  // clamped by TScrollView::SyncBoundedValueAndToggleControlStates
  // (word8c = min(word88, word8a)).
  // 0x84 — cached ownerContext (both builders store it + AssertValid). Always the
  // owning TScrollView (0x573d37/0x5744b0's `panel` argument is that TScrollView's
  // `this`) -- confirmed via TScrollView::ScrollRelative (0x573f60),
  // which reads TScrollView::contentView60/scrollBar64 at +0x60/+0x64 off this pointer.
  class TScrollView* ownerView84;
  short word88; // 0x88 — bounded-value component A (button span, seeded 0x12)
  short word8a; // 0x8a — bounded-value component B (frameHeight38 - 0x24)
  short word8c; // 0x8c — clamped current value (seeded 0x12)
  short word8e; // 0x8e — allocation padding/unobserved so far
  // 0x90 — 8-bit offscreen surface from
  // TDisplayMgr::MakeNewGWorld; released in Free().
  struct TQuickDrawSurfaceContext* surfaceContext90;

  // Inline in the original: the only construction site (0x573d37) expands to the
  // TControl base ctor + vptr store + this one field init.
  // NOOP: verified empty in original 0x00573d44
  TScrollBarView() : surfaceContext90(0) {}

  // 0x005744b0 — frame into `panel` with (4,4) margins, cache+assert the owner, seed
  // the bounded-value words, allocate the 8-bit surface for the full frame rect, and
  // build the 'scup'/'scdn' TPictureButton pair (18x18, bitmaps 0xbbb/0xbbc),
  // disabled+pressed by default.
  void InitializeScrollBar(class TScrollView* panel, int* offsetLayout, int* sizeLayout);

  // 0x005740a0 — RAII-scoped map QuickDraw context around a PrepareForDrawing() + viewport rect
  // rebuild (Draw): rect = {0, word88, frameWidth34, word8a + 0x12}.
  void RefreshCityDialogScrollableViewportWithQuickDrawContext();
  void SetThumb(int percent, unsigned char refresh); // 0x574e20
};
ASSERT_SIZE(TScrollBarView, 0x94);
