#include "StrategicMapProbe.h"

#include "MapRenderingProbe.h"
#include "RuntimeObservations.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/core/global_data_tables.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/map_ui_globals.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/ui_core/TViewMgr.h"

#include <string.h>

namespace {

bool FindVisibleTileCenters(TMapDialog* mapDialog, CPoint* first, CPoint* second) {
  bool foundFirst = false;
  for (short tile = 0; tile < 0x1950; ++tile) {
    short projectedY;
    short projectedX;
    ProjectTileIndexToWrappedScreenOffsetByScale(tile, &mapDialog->viewportOrigin, &projectedY,
                                                 &projectedX, 1);
    CPoint center(projectedX + 0x20, projectedY + 0x20);
    if (center.x < 1 || center.y < 1 || center.x >= mapDialog->frameWidth34 - 1 ||
        center.y >= mapDialog->frameHeight38 - 1) {
      continue;
    }
    if (!foundFirst) {
      *first = center;
      foundFirst = true;
    } else if (center.x != first->x || center.y != first->y) {
      *second = center;
      return true;
    }
  }
  return false;
}

// The map this probe inspects. Resolved here rather than passed in: every caller is already on the
// map, and threading the view through the boundary is what these probes exist to avoid.
TMapUberPicture* MapView() {
  return g_pViewMgr != 0 ? g_pViewMgr->mapUberPictureF0 : 0;
}

} // namespace

RuntimeActionResult StrategicMapProbe::VerifyRendering() {
  TMapUberPicture* mapView = MapView();
  if (mapView == 0 || mapView->subview2A8 == 0) {
    return RuntimeActionResult::Failure("the combined map has no map dialog");
  }
  if (!VerifyRuntimeStrategicCoastCornerComposite(mapView->subview2A8)) {
    return RuntimeActionResult::Failure(
        "strategic coast corners do not match the adjacency-selected atlas composite");
  }
  if (!VerifyRuntimeMiniMapViewportFrame(mapView->miniMapViewC0)) {
    return RuntimeActionResult::Failure(
        "mini-map viewport frame did not alter the rendered thumbnail");
  }
  if (!MapRenderingProbe::TransportConnectivityChangesTilePixels(mapView->subview2A8)) {
    return RuntimeActionResult::Failure(
        "strategic road or rail connectivity did not change the rendered tile pixels");
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult StrategicMapProbe::VerifyHoverCache() {
  TMapUberPicture* mapView = MapView();
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  TQuickDrawBlitSurface* mapCache =
      g_pPrimaryRenderSurfaceContext != 0 ? g_pPrimaryRenderSurfaceContext->GetBlitSurface() : 0;
  if (mapDialog == 0 || mapCache == 0 || mapCache->pixelBits == 0) {
    return RuntimeActionResult::Failure("combined map has no hover-test render surface");
  }

  CPoint firstHoverPoint;
  CPoint secondHoverPoint;
  if (!FindVisibleTileCenters(mapDialog, &firstHoverPoint, &secondHoverPoint)) {
    return RuntimeActionResult::Failure(
        "combined map has fewer than two projected visible tile centers");
  }

  mapDialog->RefreshControl();
  mapDialog->ForceRedraw();
  int mapCacheBytes = mapCache->stride * (mapCache->clipRect.bottom - mapCache->clipRect.top);
  unsigned char* beforeHover = new unsigned char[mapCacheBytes];
  memcpy(beforeHover, mapCache->pixelBits, mapCacheBytes);
  short savedStrategicNeighbors[6];
  short savedCitySiteNeighbors[6];
  memcpy(savedStrategicNeighbors, g_aStrategicMapNeighborHighlightTiles_00697310,
         sizeof(savedStrategicNeighbors));
  memcpy(savedCitySiteNeighbors, g_aCitySiteNeighborHighlightTiles_00697320,
         sizeof(savedCitySiteNeighbors));
  for (int neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
    g_aStrategicMapNeighborHighlightTiles_00697310[neighborIndex] = -1;
    g_aCitySiteNeighborHighlightTiles_00697320[neighborIndex] = -1;
  }
  g_aCitySiteNeighborHighlightTiles_00697320[0] = 0;

  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags;
  GetGWorld(&savedSurface, &savedSurfaceFlags);
  short savedInteractionMode = mapView->activeUnitCategoryIndex96;
  mapView->activeUnitCategoryIndex96 = 5;
  mapDialog->HandleCursorHoverSelectionByChildHitTestAndFallback(&firstHoverPoint, 0);
  bool firstHoverKeptCache = memcmp(beforeHover, mapCache->pixelBits, mapCacheBytes) == 0;
  mapDialog->HandleCursorHoverSelectionByChildHitTestAndFallback(&secondHoverPoint, 0);
  bool secondHoverKeptCache = memcmp(beforeHover, mapCache->pixelBits, mapCacheBytes) == 0;
  bool usedStrategicNeighborCache = g_aCitySiteNeighborHighlightTiles_00697320[0] == 0;
  for (int checkedNeighborIndex = 0; checkedNeighborIndex < 6; ++checkedNeighborIndex) {
    if (g_aStrategicMapNeighborHighlightTiles_00697310[checkedNeighborIndex] != -1) {
      usedStrategicNeighborCache = false;
    }
  }
  memcpy(g_aStrategicMapNeighborHighlightTiles_00697310, savedStrategicNeighbors,
         sizeof(savedStrategicNeighbors));
  memcpy(g_aCitySiteNeighborHighlightTiles_00697320, savedCitySiteNeighbors,
         sizeof(savedCitySiteNeighbors));
  mapView->activeUnitCategoryIndex96 = savedInteractionMode;
  SetGWorld(savedSurface, savedSurfaceFlags);
  delete[] beforeHover;

  if (!firstHoverKeptCache || !secondHoverKeptCache || !usedStrategicNeighborCache) {
    return RuntimeActionResult::Failure(
        "combined-map hover retained transient selection pixels in the map cache");
  }
  if (!MapRenderingProbe::HoverMovementRestoresPreviousTiles(mapDialog, -1)) {
    return RuntimeActionResult::Failure(
        "combined-map hover movement did not restore the previous tile's window pixels");
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult StrategicMapProbe::VerifyScrolling() {
  TMapUberPicture* mapView = MapView();
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0) {
    return RuntimeActionResult::Failure("combined map has no scrollable map dialog");
  }
  g_MapInteractionPreviewPoint_006a3370 =
      CPoint(0, 0); // RUNTIME_COORDINATE_EXPLAINED: reset production preview geometry
  if (g_pGlobalMapState->hexNeighborWrapHorizontally == 0) {
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(0x6b, 0, 0);
    mapView->Scroll(4);
    if (mapDialog->viewportOrigin.x != 0) {
      return RuntimeActionResult::Failure(
          "combined-map right-edge scrolling did not wrap to the left edge");
    }
    mapView->Scroll(8);
    if (mapDialog->viewportOrigin.x != 0x6b * 0x40) {
      return RuntimeActionResult::Failure(
          "combined-map left-edge scrolling did not wrap to the right edge");
    }
  } else {
    int rightColumn = 0x6e - g_wMapDialogViewportTileSpan;
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(0x7fff, 0, 0);
    if (mapDialog->viewportOrigin.x != rightColumn * 0x40) {
      return RuntimeActionResult::Failure(
          "combined-map scrolling stopped before the full right edge");
    }
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(-0x7fff, 0, 0);
    if (mapDialog->viewportOrigin.x != 0x40) {
      return RuntimeActionResult::Failure(
          "combined-map scrolling stopped before the full left edge");
    }
  }
  mapDialog->SetMapDialogCellCoordinatesAndRefresh(1, 0x7fff, 0);
  if (mapDialog->viewportOrigin.y != 0x35 * 0x40) {
    return RuntimeActionResult::Failure(
        "combined-map scrolling stopped before the full bottom edge");
  }
  mapDialog->SetMapDialogCellCoordinatesAndRefresh(1, -0x7fff, 0);
  if (mapDialog->viewportOrigin.y != 0) {
    return RuntimeActionResult::Failure("combined-map scrolling stopped before the full top edge");
  }
  return RuntimeActionResult::Success();
}
