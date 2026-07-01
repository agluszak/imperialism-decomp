#include "game/TScrollView.h"

#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x0043d7f0
// TScrollView::`scalar deleting destructor'
TScrollView::~TScrollView() {}
IMPLEMENT_DYNCREATE(TScrollView, TView)

TScrollView::TScrollView() {}

// FUNCTION: IMPERIALISM 0x00573ce0
void TScrollView::NoOpUiLifecycleHook(int arg) {
}

// Clip painting to this scroll view's own frame: select a rect region covering the
// slot-0x57 bounds into the paint DC, run the base TView child-paint recursion, then
// clear the DC's clip region again. (The CRgn is deleted right after SelectClipRgn —
// the DC keeps its own copy of the region.)
// FUNCTION: IMPERIALISM 0x005742b0
void TScrollView::PaintVisibleChildrenIntersectingClipRect(RECT* clipRect, CDC* paintDc) {
  if (GetMcAppUiActiveFlag() == 0 || IsActionable() == 0 || Refresh() == 0) {
    return;
  }
  RECT bounds;
  CopyRectFromBuildRectFromSlot158(&bounds);
  {
    CRgn clipRgn;
    clipRgn.Attach(::CreateRectRgnIndirect(&bounds));
    paintDc->SelectClipRgn(&clipRgn);
    clipRgn.DeleteObject();
  }
  TView::PaintVisibleChildrenIntersectingClipRect(clipRect, paintDc);
  paintDc->SelectClipRgn(0);
}
