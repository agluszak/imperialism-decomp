#include "game/TCitySiteView.h"

#include "game/CString.h"
#include "game/TDisplayMgr.h"
#include "game/TInfoBarText.h"
#include "game/TMapMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

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
  // Explicitly skips TMapDialog::NoOpUiLifecycleHook (an empty override, 0x519d30) and
  // calls straight through to TWorldView's -- confirmed by the real call target (0x595090)
  // in the disassembly.
  TWorldView::NoOpUiLifecycleHook(arg);

  projectionScale76 = 1;
  previewSquareRadius78 = 0x40;

  RECT surfaceBounds = {0, 0, 0x1680, 0x40};
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&quickDrawSurface350, 8, &surfaceBounds);

  ResetAllTileMarkersToSentinel();

  g_pCitySiteCachedPrimaryRenderSurfaceContext = g_pPrimaryRenderSurfaceContext;
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagGold /* 'DLOG' */);

  // TCitySiteView is always hosted as TMapUberPicture's 'DLOG' child (see
  // TMapUberPicture.h's "event 0x3b8 constructs a TCitySiteView" note and the real
  // construction site in turn_event_dialog_factory.cpp), and this dispatch is a direct
  // (non-virtual, fixed-address) call, not a vtable call -- consistent with the compiler
  // knowing ownerContext's concrete type here.
  static_cast<TMapUberPicture*>(ownerContext)->SetMapInteractionMode(4);

  minColBound368 = 1000;
  maxColBound36c = -1000;
  minRowBound370 = 1000;
  maxRowBound374 = -1000;

  short activeNationId = g_pSimMgr->GetActiveNationId();
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    if (activeNationId != g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04) {
      continue;
    }
    short row;
    short col;
    SplitTileIndexToRowAndColumn(static_cast<short>(tileIndex), &row, &col);
    if (row < minRowBound370) {
      minRowBound370 = row;
    }
    if (col < minColBound368) {
      minColBound368 = col;
    }
    row = static_cast<short>(row - 5);
    col = static_cast<short>(col + (3 - g_wMapDialogViewportTileSpan));
    if (row > maxRowBound374) {
      maxRowBound374 = row;
    }
    if (col > maxColBound36c) {
      maxColBound36c = col;
    }
  }
  minColBound368 -= 1;
  minRowBound370 -= 1;

  g_pCursorControlPanel = static_cast<TInfoBarText*>(
      static_cast<TView*>(g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagCurs)));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x273f, 9, kControlTagCanc);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2730, 3, kControlTagQuer);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagGold /* 'DLOG' */);
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
