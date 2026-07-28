#include "game/map_ui/TCitySiteView.h"
#include "game/ui_tags_common.h"

#include "game/ui_screens/CString.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TTown.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/map_ui_globals.h"
#include "game/globals/shared_globals.h"
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
// FUNCTION: IMPERIALISM 0x0051bfd0
TCitySiteView::~TCitySiteView() {}

// FUNCTION: IMPERIALISM 0x0051bff0
void TCitySiteView::DoPostCreate(int arg) {
  // Explicitly skips TMapDialog::DoPostCreate (an empty override, 0x519d30) and
  // calls straight through to TWorldView's -- confirmed by the real call target (0x595090)
  // in the disassembly.
  TWorldView::DoPostCreate(arg);

  projectionScale = 1;
  previewSquareRadius = 0x40;

  RECT surfaceBounds = {0, 0, 0x1680, 0x40};
  g_pDisplayMgr->MakeNewGWorld(quickDrawSurface350, 8, surfaceBounds);

  ResetAllTileMarkersToSentinel();

  g_pCitySiteCachedPrimaryRenderSurfaceContext = g_pPrimaryRenderSurfaceContext;
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagDialog);

  // TCitySiteView is always hosted as TMapUberPicture's 'DLOG' child (see
  // TMapUberPicture.h's "event 0x3b8 constructs a TCitySiteView" note and the real
  // construction site in turn_event_dialog_factory.cpp), and this dispatch is a direct
  // (non-virtual, fixed-address) call, not a vtable call -- consistent with the compiler
  // knowing ownerContext's concrete type here.
  static_cast<TMapUberPicture*>(ownerContext)->SetMapInteractionMode(4);

  minColumn = 1000;
  maxColumn = -1000;
  minRow = 1000;
  maxRow = -1000;

  short activeNationId = g_pSimMgr->GetActiveNationId();
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    if (activeNationId != g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04) {
      continue;
    }
    short tileRow;
    short tileColumn;
    SplitTileIndexToRowAndColumn(static_cast<short>(tileIndex), &tileRow, &tileColumn);
    if (tileRow < minRow) {
      minRow = tileRow;
    }
    if (tileColumn < minColumn) {
      minColumn = tileColumn;
    }
    tileRow = static_cast<short>(tileRow - 5);
    tileColumn = static_cast<short>(tileColumn + (3 - g_wMapDialogViewportTileSpan));
    if (tileRow > maxRow) {
      maxRow = tileRow;
    }
    if (tileColumn > maxColumn) {
      maxColumn = tileColumn;
    }
  }
  minColumn -= 1;
  minRow -= 1;

  g_pCursorControlPanel = static_cast<TInfoBarText*>(
      static_cast<TView*>(g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagCurs)));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x273f, 9, kControlTagCanc);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2730, 3, kControlTagQuer);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagDialog);
}

// FUNCTION: IMPERIALISM 0x0051c2a0
void TCitySiteView::SetMapViewTileIndex(int tileIndex) {
  union WordOutputInt {
    int value;
    short word;
  };
  WordOutputInt row;
  WordOutputInt column;
  row.value = tileIndex;
  SplitTileIndexToRowAndColumn(static_cast<short>(tileIndex), &row.word, &column.word);
  SetMapViewCellCoordinates(column.value, row.value);
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
  if (c < minColumn) {
    c = static_cast<short>(minColumn);
  }
  if (r < minRow) {
    r = static_cast<short>(minRow);
  }
  if (c > maxColumn) {
    c = static_cast<short>(maxColumn);
  }
  if (r > maxRow) {
    r = static_cast<short>(maxRow);
  }
  TMapDialog::SetMapDialogCellCoordinatesAndRefresh(c, r, mode);
}

// FUNCTION: IMPERIALISM 0x0051c3b0
void TCitySiteView::RenderStrategicTileSelectionAndNeighborHighlights() {
  short neighborTiles[6] = {-1, -1, -1, -1, -1, -1};
  bool updateNeighborHighlights = false;
  short currentTile = static_cast<short>(hoveredTileIndex);

  if (g_pGlobalMapState->terrainStateTable[currentTile].recruitSearchVisited0e == 0) {
    updateNeighborHighlights = true;
    TMapMgr::GetNeighborTileIDArray(currentTile, neighborTiles,
                                    g_pGlobalMapState->hexNeighborWrapHorizontally);
    short activeNation = g_pSimMgr->GetActiveNationId();
    for (int i = 0; i < 6; ++i) {
      short neighbor = neighborTiles[i];
      if (neighbor != -1 &&
          g_pGlobalMapState->terrainStateTable[neighbor].ownerNationTag04 != activeNation &&
          g_pGlobalMapState->terrainStateTable[neighbor].GetTerrainKind() !=
              kStrategicTerrainWater) {
        neighborTiles[i] = -1;
      }
    }
  }

  short previousTile = static_cast<short>(paintedHoverTileIndex);
  signed char previousMarker = g_pGlobalMapState->terrainStateTable[previousTile].markerSlotIndex10;
  if (previousMarker != -1 && tileMarkers7c[previousMarker].flag != 0) {
    short projectedY;
    short projectedX;
    ProjectTileIndexToWrappedScreenOffsetByScale(previousTile, &viewportOrigin, &projectedY,
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
    ProjectTileIndexToWrappedScreenOffsetByScale(oldNeighbor, &viewportOrigin, &projectedY,
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
    ProjectTileIndexToWrappedScreenOffsetByScale(currentTile, &viewportOrigin, &projectedY,
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
void TCitySiteView::HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) {
  (void)nInputFlags;

  TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[nTileIndex];
  StrategicTerrainKind terrainKind = tile.GetTerrainKind();
  signed char ownerNation = tile.ownerNationTag04;
  short activeNation = g_pSimMgr->GetActiveNationId();

  if (ownerNation != activeNation) {
    PlayDefaultMessageBeep(1);
    CString message;
    g_pSimMgr->GetString(0x273b, terrainKind == kStrategicTerrainWater ? 3 : 0, &message);
    g_pDisplayMgr->ModalMessage(message, g_MapInteractionPreviewPoint_006a3370);
    return;
  }

  bool supportsCitySite =
      terrainKind == kStrategicTerrainPlains || terrainKind == kStrategicTerrainFarmland ||
      terrainKind == kStrategicTerrainForest || terrainKind == kStrategicTerrainDesert;
  if (!supportsCitySite ||
      !g_pGlobalMapState->IsValidSecondaryNationHomeTileCandidate(nTileIndex)) {
    PlayDefaultMessageBeep(1);
    CString message;
    if (supportsCitySite && g_pGlobalMapState->CanBuildPortAtTile(nTileIndex)) {
      g_pSimMgr->GetString(0x273b, 2, &message);
    } else {
      g_pSimMgr->GetString(0x273b, 1, &message);
    }
    g_pDisplayMgr->ModalMessage(message, g_MapInteractionPreviewPoint_006a3370);
    return;
  }

  pendingTown->tileIndex = nTileIndex;
  CString cityName;
  g_pGlobalMapState->AssignCityRecordDisplayName(tile.cityRecordIndex, &cityName);
  pendingTown->SetName(cityName);
  if (!g_pUiRuntimeContext->ShowNewCityDialog(pendingTown)) {
    pendingTown->tileIndex = 0;
    return;
  }

  g_pGlobalMapState->PlaceCity(nTileIndex, activeNation);
  g_pSimMgr->StartNextPhase();
}
