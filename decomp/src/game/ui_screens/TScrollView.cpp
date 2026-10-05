#include "game/ui_screens/TScrollView.h"
#include "game/ui_tags_common.h"

#include "game/ui_screens/TScrollBarView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

// FUNCTION: IMPERIALISM 0x0043d820
TScrollView::~TScrollView() {}

IMPLEMENT_DYNCREATE(TScrollView, TView)

// FUNCTION: IMPERIALISM 0x00573cb0
void TScrollView::IScrollView(TView* panel, int* offsetLayout, int* sizeLayout) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 5, 5, 0);
}

// Not a no-op despite the inherited slot name: resolve the 'scro'-tagged content
// view, then build the companion scrollbar docked to the right edge (width 0x19,
// full height).
// FUNCTION: IMPERIALISM 0x00573ce0
void TScrollView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  contentView = ResolveControlByTag(kControlTagScro); // 'scro'
  TScrollBarView* bar = new TScrollBarView();
  int barOffset[2];
  int barSize[2];
  barSize[1] = frameHeight;
  barOffset[0] = frameWidth - 0x19;
  barSize[0] = 0x19;
  barOffset[1] = 0;
  bar->InitializeScrollBar(this, barOffset, barSize);
  scrollBar = bar;
}

// FUNCTION: IMPERIALISM 0x00573e40
void TScrollView::ScrollOnce(int direction) {
  switch (direction) {
  case 0:
    ScrollRelative(0, 0xc);
    return;
  case 1:
    ScrollRelative(0, -0xc);
    return;
  case 2:
    ScrollRelative(0xc, 0);
    return;
  case 3:
    ScrollRelative(-0xc, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00573ed0
void TScrollView::ScrollPage(int direction) {
  switch (direction) {
  case 0:
    ScrollRelative(0, -static_cast<short>(frameHeight));
    return;
  case 1:
    ScrollRelative(0, static_cast<short>(frameHeight));
    return;
  case 2:
    ScrollRelative(0xc, 0);
    return;
  case 3:
    ScrollRelative(-0xc, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00573f60
void TScrollView::ScrollRelative(short horizontalDelta, short verticalDelta) {
  if (contentView == nullptr) {
    return;
  }
  short heightDiff = static_cast<short>(contentView->frameHeight) - static_cast<short>(frameHeight);
  if (heightDiff <= 0) {
    return;
  }

  CPoint origin;
  int baseX = contentView->ownerLocalX;
  int baseY = contentView->ownerLocalY;
  origin.x = baseX + horizontalDelta;
  origin.y = baseY + verticalDelta;
  if (contentView->frameWidth < origin.x) {
    origin.x = contentView->frameWidth;
  }
  if (origin.x < 0) {
    origin.x = 0;
  }
  if (origin.y < -heightDiff) {
    origin.y = -heightDiff;
  } else if (origin.y > 0) {
    origin.y = 0;
  }

  contentView->Locate(origin, 1);

  short trackRange = scrollBar->word8a - scrollBar->word88;
  short newValue =
      static_cast<short>(scrollBar->word88 - origin.y * 1024 / heightDiff * trackRange / 1024);
  if (newValue < scrollBar->word88) {
    scrollBar->word8c = scrollBar->word88;
    scrollBar->RefreshCityDialogScrollableViewportWithQuickDrawContext();
    return;
  }
  if (newValue > scrollBar->word8a) {
    newValue = scrollBar->word8a;
  }
  scrollBar->word8c = newValue;
  scrollBar->RefreshCityDialogScrollableViewportWithQuickDrawContext();
}

// FUNCTION: IMPERIALISM 0x00574160
void TScrollView::ScrollToPercent(int percent) {
  if (contentView != 0) {
    short heightDiff =
        static_cast<short>(contentView->frameHeight) - static_cast<short>(frameHeight);
    if (heightDiff > 0) {
      CPoint origin(
          contentView->ownerLocalX,
          -static_cast<short>((percent * heightDiff + (percent * heightDiff >> 31 & 0x3ff)) >> 10));
      contentView->Locate(origin, 1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005741e0
void TScrollView::SyncBoundedValueAndToggleControlStates() {
  CPoint contentOrigin;
  contentOrigin.x = contentView->ownerLocalX;
  contentOrigin.y = 0;
  contentView->Locate(contentOrigin, 1);

  TScrollBarView* bar = scrollBar;
  bar->word8c = bar->word88;
  if (bar->word88 > bar->word8a) {
    bar->word8c = bar->word8a;
  }

  if (contentView->frameHeight - frameHeight > 0) {
    scrollBar->Show(1, 1);
    scrollBar->ViewEnable(1, 1);
  } else {
    scrollBar->Show(0, 1);
    scrollBar->ViewEnable(0, 1);
  }
}

// FUNCTION: IMPERIALISM 0x005742b0
void TScrollView::PaintVisibleChildrenIntersectingClipRect(RECT* clipRect, CDC* paintDc) {
  if (GetMcAppUiActiveFlag() == 0 || !IsActionable() || PrepareForDrawing() == 0) {
    return;
  }
  CRect bounds;
  GetDrawableQDRect(&bounds);
  {
    CRgn clipRgn;
    clipRgn.Attach(::CreateRectRgnIndirect(&bounds));
    paintDc->SelectClipRgn(&clipRgn);
    clipRgn.DeleteObject();
  }
  TView::PaintVisibleChildrenIntersectingClipRect(clipRect, paintDc);
  paintDc->SelectClipRgn(0);
}
