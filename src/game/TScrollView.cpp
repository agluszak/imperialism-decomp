#include "game/TScrollView.h"

#include "game/TScrollBarView.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x0043d7f0
// TScrollView::`scalar deleting destructor'
TScrollView::~TScrollView() {}
// SYNTHETIC: IMPERIALISM 0x00573c20
// TScrollView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00573c90
// TScrollView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TScrollView, TView)

// FUNCTION: IMPERIALISM 0x00573cb0
void TScrollView::ConstructTScrollViewBaseState(TView* panel, int* offsetLayout, int* sizeLayout) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 5, 5, 0);
}

// Not a no-op despite the inherited slot name: resolve the 'scro'-tagged content
// view, then build the companion scrollbar docked to the right edge (width 0x19,
// full height).
// FUNCTION: IMPERIALISM 0x00573ce0
void TScrollView::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);
  contentView60 = ResolveControlByTag(0x7363726f); // 'scro'
  TScrollBarView* bar = new TScrollBarView();
  int barOffset[2];
  int barSize[2];
  barSize[1] = frameHeight38;
  barOffset[0] = frameWidth34 - 0x19;
  barSize[0] = 0x19;
  barOffset[1] = 0;
  bar->ConstructTScrollBarViewBaseState(this, barOffset, barSize);
  scrollBar64 = bar;
}

// FUNCTION: IMPERIALISM 0x005741e0
void TScrollView::SyncBoundedValueAndToggleControlStates() {
  POINT contentOrigin;
  contentOrigin.x = contentView60->ownerLocalX;
  contentOrigin.y = 0;
  contentView60->CaptureLayoutF0(reinterpret_cast<int*>(&contentOrigin), 1);

  TScrollBarView* bar = scrollBar64;
  bar->word8c = bar->word88;
  if (bar->word88 > bar->word8a) {
    bar->word8c = bar->word8a;
  }

  if (contentView60->frameHeight38 - frameHeight38 > 0) {
    scrollBar64->SetEnabled(1, 1);
    scrollBar64->SetState(1, 1);
  } else {
    scrollBar64->SetEnabled(0, 1);
    scrollBar64->SetState(0, 1);
  }
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
