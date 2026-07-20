#include "game/TCitySiteView.h"
// SYNTHETIC: IMPERIALISM 0x0051bd60
// TCitySiteView::CreateObject

// SYNTHETIC: IMPERIALISM 0x0051be90
// TCitySiteView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCitySiteView, TMapDialog)

// FUNCTION: IMPERIALISM 0x0051beb0
TCitySiteView::TCitySiteView() {}

// SYNTHETIC: IMPERIALISM 0x0051bfa0
// TCitySiteView::`scalar deleting destructor'
TCitySiteView::~TCitySiteView() {}

// FUNCTION: IMPERIALISM 0x0051bff0
void TCitySiteView::NoOpUiLifecycleHook(int arg) {
  TMapDialog::NoOpUiLifecycleHook(arg);

  minColBound368 = 1000;
  maxColBound36c = -1000;
  minRowBound370 = 1000;
  maxRowBound374 = -1000;

  // The original also writes two TMapDialog-inherited short fields at +0x76/+0x78 (not yet
  // declared -- outside TCitySiteView's own +0x364 region), resolves the active document's
  // 'GLOG'/'main' controls via a doc-mapping global, and computes further per-nation tile
  // bounds (TSimMgr::GetActiveNationId, a per-nation table at 0x6a43d4) before dispatching
  // through vtable slot 0x1f8 (beyond TView's declared extent) -- left unmodeled.
}

// FUNCTION: IMPERIALISM 0x0051c2a0
void TCitySiteView::SetMapViewTileIndex(int arg1) {
  (void)arg1;
}

// FUNCTION: IMPERIALISM 0x0051c2f0
void TCitySiteView::SetMapViewCellCoordinates(int arg1, int arg2) {
  SetMapDialogCellCoordinatesAndRefresh(arg1, arg2, 0);
}

// The original keeps col/row as word registers throughout (the clamp writes replace only
// the low word), hence the short locals seeded from the int slot params.
// FUNCTION: IMPERIALISM 0x0051c320
void TCitySiteView::SetMapDialogCellCoordinatesAndRefresh(int col, int row, int mode) {
  short c = static_cast<short>(col);
  short r = static_cast<short>(row);
  if (c < minColBound368) {
    c = static_cast<short>(minColBound368);
  }
  if (r < minRowBound370) {
    r = static_cast<short>(minRowBound370);
  }
  if (c > maxColBound36c) {
    c = static_cast<short>(maxColBound36c);
  }
  if (r > maxRowBound374) {
    r = static_cast<short>(maxRowBound374);
  }
  TMapDialog::SetMapDialogCellCoordinatesAndRefresh(c, r, mode);
}

// FUNCTION: IMPERIALISM 0x0051c3b0
void TCitySiteView::RenderStrategicTileSelectionAndNeighborHighlights() {}

// FUNCTION: IMPERIALISM 0x0051c760
void TCitySiteView::HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) {}
