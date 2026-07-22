#include "game/TCitySiteView.h"

#include "game/CString.h"
#include "game/TDisplayMgr.h"
#include "game/TInfoBarText.h"
#include "game/TMapMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
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
void TCitySiteView::DoPostCreate(int arg) {
  // Explicitly skips TMapDialog::DoPostCreate (an empty override, 0x519d30) and
  // calls straight through to TWorldView's -- confirmed by the real call target (0x595090)
  // in the disassembly.
  TWorldView::DoPostCreate(arg);

  projectionScale76 = 1;
  previewSquareRadius78 = 0x40;

  RECT surfaceBounds = {0, 0, 0x1680, 0x40};
  g_pDisplayMgr->MakeNewGWorld(quickDrawSurface350, 8, surfaceBounds);

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
  int col;
  SplitTileIndexToRowAndColumn(static_cast<short>(arg1), reinterpret_cast<short*>(&arg1),
                               reinterpret_cast<short*>(&col));
  SetMapViewCellCoordinates(col, arg1);
}

// FUNCTION: IMPERIALISM 0x0051c2f0
void TCitySiteView::SetMapViewCellCoordinates(int column, int row) {
  SetMapDialogCellCoordinatesAndRefresh(column, row, 0);
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
void TCitySiteView::RenderStrategicTileSelectionAndNeighborHighlights() {
  short neighborTiles[6] = {-1, -1, -1, -1, -1, -1};
  bool updateNeighborHighlights = false;
  short currentTile = static_cast<short>(hoveredTileIndex6c);

  if (g_pGlobalMapState->terrainStateTable[currentTile].recruitSearchVisited0e == 0) {
    updateNeighborHighlights = true;
    TMapMgr::ComputeHexNeighborTileIndices(currentTile, neighborTiles,
                                           g_pGlobalMapState->hexNeighborWrapHorizontally20);
    short activeNation = g_pSimMgr->GetActiveNationId();
    for (int i = 0; i < 6; ++i) {
      short neighbor = neighborTiles[i];
      if (neighbor != -1 &&
          g_pGlobalMapState->terrainStateTable[neighbor].ownerNationTag04 != activeNation &&
          g_pGlobalMapState->terrainStateTable[neighbor].terrainType00 != 5) {
        neighborTiles[i] = -1;
      }
    }
  }

  short previousTile = static_cast<short>(paintedHoverTileIndex6e);
  signed char previousMarker = g_pGlobalMapState->terrainStateTable[previousTile].markerSlotIndex10;
  if (previousMarker != -1 && tileMarkers7c[previousMarker].flag != 0) {
    short projectedY;
    short projectedX;
    ProjectTileIndexToWrappedScreenOffsetByScale(previousTile, &viewportOrigin60, &projectedY,
                                                 &projectedX, 1);
    RECT sourceRect = {projectedX + 0x40, projectedY + 0x40, projectedX + 0x80, projectedY + 0x80};
    RECT destinationRect = {projectedX, projectedY, projectedX + 0x40, projectedY + 0x40};
    BlitRectWithOptionalTransparency(g_pCitySiteCachedPrimaryRenderSurfaceContext->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect, &destinationRect, 0, 0);
  }

  for (int oldIndex = 0; oldIndex < 6; ++oldIndex) {
    short oldNeighbor = g_aStrategicMapNeighborHighlightTiles_00697320[oldIndex];
    if (oldNeighbor == -1) {
      continue;
    }
    signed char oldMarker = g_pGlobalMapState->terrainStateTable[oldNeighbor].markerSlotIndex10;
    if (oldMarker == -1 || tileMarkers7c[oldMarker].flag == 0) {
      continue;
    }

    short projectedY;
    short projectedX;
    ProjectTileIndexToWrappedScreenOffsetByScale(oldNeighbor, &viewportOrigin60, &projectedY,
                                                 &projectedX, 1);
    RECT sourceRect = {projectedX + 0x40, projectedY + 0x40, projectedX + 0x80, projectedY + 0x80};
    RECT destinationRect = {projectedX, projectedY, projectedX + 0x40, projectedY + 0x40};
    BlitRectWithOptionalTransparency(g_pCitySiteCachedPrimaryRenderSurfaceContext->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect, &destinationRect, 0, 0);
  }

  if (updateNeighborHighlights) {
    short projectedY;
    short projectedX;
    ProjectTileIndexToWrappedScreenOffsetByScale(currentTile, &viewportOrigin60, &projectedY,
                                                 &projectedX, 1);
    RECT currentTileRect = {projectedX, projectedY, projectedX + 0x40, projectedY + 0x40};
    QDFrameRect(&currentTileRect);
    DrawHexNeighborOutlineFromTileArray(neighborTiles);
  }

  for (int newIndex = 0; newIndex < 6; ++newIndex) {
    g_aStrategicMapNeighborHighlightTiles_00697320[newIndex] =
        updateNeighborHighlights ? neighborTiles[newIndex] : -1;
  }
}

// FUNCTION: IMPERIALISM 0x0051c760
void TCitySiteView::HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) {}
