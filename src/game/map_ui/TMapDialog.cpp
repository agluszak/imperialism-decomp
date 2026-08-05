#include "game/map_ui/TMapDialog.h"
#include "game/resource_domain_types.h"
#include "game/ui_tags_common.h"

#include <stdlib.h>
#include <string.h>
#include "game/app/TAnimator.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/app/TCivAnimation2.h"
#include "game/city_ui/TCivMgr.h"
#include "game/military/TCivUnit.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/core/TMouseCaptureState.h"
#include "game/military/TMilitaryUnit.h"
#include "game/navy/TOcean.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/gfx/CTemporaryRegion.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"

#ifdef IMPERIALISM_RUNTIME_TESTS
namespace {
short g_runtimeObservedStrategicMapTile;
short g_runtimeObservedStrategicMapResource;
bool g_runtimeObservedStrategicMapResourceDraw;
short g_runtimeObservedStrategicMapSurveyMissTile;
bool g_runtimeObservedStrategicMapSurveyMissDraw;
short g_runtimeObservedStrategicMapImprovementTile;
short g_runtimeObservedStrategicMapImprovementResource;
short g_runtimeObservedStrategicMapImprovementClass;
bool g_runtimeObservedStrategicMapImprovementDraw;
} // namespace

void ObserveStrategicMapResourceTileForRuntimeTest(short tileIndex, short resourceType) {
  g_runtimeObservedStrategicMapTile = tileIndex;
  g_runtimeObservedStrategicMapResource = resourceType;
  g_runtimeObservedStrategicMapResourceDraw = false;
}

bool WasStrategicMapResourceTileObservedForRuntimeTest() {
  return g_runtimeObservedStrategicMapResourceDraw;
}

void ObserveStrategicMapSurveyMissTileForRuntimeTest(short tileIndex) {
  g_runtimeObservedStrategicMapSurveyMissTile = tileIndex;
  g_runtimeObservedStrategicMapSurveyMissDraw = false;
}

bool WasStrategicMapSurveyMissTileObservedForRuntimeTest() {
  return g_runtimeObservedStrategicMapSurveyMissDraw;
}

void ObserveStrategicMapImprovementTileForRuntimeTest(short tileIndex, short resourceType,
                                                      short improvementClass) {
  g_runtimeObservedStrategicMapImprovementTile = tileIndex;
  g_runtimeObservedStrategicMapImprovementResource = resourceType;
  g_runtimeObservedStrategicMapImprovementClass = improvementClass;
  g_runtimeObservedStrategicMapImprovementDraw = false;
}

bool WasStrategicMapImprovementTileObservedForRuntimeTest() {
  return g_runtimeObservedStrategicMapImprovementDraw;
}

#define IMPERIALISM_RUNTIME_OBSERVE_STRATEGIC_RESOURCE(tileIndex, resourceType)                    \
  do {                                                                                             \
    if ((tileIndex) == g_runtimeObservedStrategicMapTile &&                                        \
        (resourceType) == g_runtimeObservedStrategicMapResource) {                                 \
      g_runtimeObservedStrategicMapResourceDraw = true;                                            \
    }                                                                                              \
  } while (0)
#define IMPERIALISM_RUNTIME_OBSERVE_STRATEGIC_SURVEY_MISS(tileIndex)                               \
  do {                                                                                             \
    if ((tileIndex) == g_runtimeObservedStrategicMapSurveyMissTile) {                              \
      g_runtimeObservedStrategicMapSurveyMissDraw = true;                                          \
    }                                                                                              \
  } while (0)
#define IMPERIALISM_RUNTIME_OBSERVE_STRATEGIC_IMPROVEMENT(tileIndex, resourceType,                 \
                                                          improvementClass)                        \
  do {                                                                                             \
    if ((tileIndex) == g_runtimeObservedStrategicMapImprovementTile &&                             \
        (resourceType) == g_runtimeObservedStrategicMapImprovementResource &&                      \
        (improvementClass) == g_runtimeObservedStrategicMapImprovementClass) {                     \
      g_runtimeObservedStrategicMapImprovementDraw = true;                                         \
    }                                                                                              \
  } while (0)
#else
#define IMPERIALISM_RUNTIME_OBSERVE_STRATEGIC_RESOURCE(tileIndex, resourceType) ((void)0)
#define IMPERIALISM_RUNTIME_OBSERVE_STRATEGIC_SURVEY_MISS(tileIndex) ((void)0)
#define IMPERIALISM_RUNTIME_OBSERVE_STRATEGIC_IMPROVEMENT(tileIndex, resourceType,                 \
                                                          improvementClass)                        \
  ((void)0)
#endif
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/map_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/pointer_representation.h"

void NormalizeWrappedMapCoord108x60(short* xCoord, short* yCoord);

static inline double DefaultMapCellScale() {
  return 0.015625;
}

static inline int DivideMapPixelOffsetBy64(int value) {
  if (value < 0) {
    value += 0x3f;
  }
  return value >> 6;
}

static inline void CopyPixelDword(unsigned char* destination, const unsigned char* source) {
  int pixelWord;
  memcpy(&pixelWord, source, sizeof(pixelWord));
  memcpy(destination, &pixelWord, sizeof(pixelWord));
}

static inline bool LandTilesHaveDifferentNationOwners(short firstTile, short secondTile) {
  if (firstTile == -1 || secondTile == -1) {
    return false;
  }
  const TTerrainStateRecord& first = g_pGlobalMapState->terrainStateTable[firstTile];
  const TTerrainStateRecord& second = g_pGlobalMapState->terrainStateTable[secondTile];
  return first.GetTerrainKind() != kStrategicTerrainWater &&
         second.GetTerrainKind() != kStrategicTerrainWater &&
         first.ownerNationTag04 != second.ownerNationTag04;
}

static inline void SetMapBorderColorForTileOwner(short tileIndex) {
  short nation = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04;
  if (g_pDiplomacyTurnStateManager->IsGreatPower(nation) == 0) {
    nation = 0x35;
  }
  g_pViewMgr->SetForeColor(nation);
}

static inline void Blit64x64StrategicMapAtlasTile(TQuickDrawSurfaceContext* atlas,
                                                  TQuickDrawSurfaceContext* destination,
                                                  int sourceOffset, CRect& destinationRect) {
  if (atlas == 0 || destination == 0) {
    return;
  }
  CRect sourceRect(sourceOffset, 0, sourceOffset + 0x40, 0x40);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(atlas->GetBlitSurface(), destination->GetBlitSurface(),
                                   &sourceRect, &destinationRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

double g_mapCellRowScale_006a3360 = DefaultMapCellScale();
double g_mapCellColumnScale_006a3388 = DefaultMapCellScale();

// Genuine __cdecl free function (bare RET; every caller cleans the 0x14 arg bytes) — not a
// TMapDialog member, despite living among the map-dialog projection code. The vertical
// (row-based) output is the THIRD parameter and the horizontal the fourth — the original
// stores through [esp+0x18] for Y and [esp+0x1c] for X.
// FUNCTION: IMPERIALISM 0x00512440
void ProjectTileIndexToWrappedScreenOffsetByScale(short tileIndex, const CPoint* viewportOrigin,
                                                  short* outY, short* outX, short scale) {
  unsigned int row = static_cast<unsigned int>(tileIndex / 0x6c);
  *outY = static_cast<short>(row) * 0x40 - static_cast<short>(viewportOrigin->y);
  short projectedX =
      static_cast<short>((tileIndex % 0x6c) << 6) - static_cast<short>(viewportOrigin->x);
  *outX = projectedX;
  if ((row & 1U) != 0) {
    projectedX = static_cast<short>(projectedX + 0x20);
    *outX = projectedX;
    if (projectedX >= 0x1ae0) {
      *outX = static_cast<short>(projectedX - 0x1b00);
    }
  }
  while (*outX < -0x40) {
    *outX = static_cast<short>(*outX + 0x1b00);
  }
  *outY = static_cast<short>(*outY / scale);
  *outX = static_cast<short>(*outX / scale);
}

// The retail CRT initializer computes the nine staggered columns covered by the
// 512-pixel map viewport and writes only the low word of the BSS-backed dword. Keep the
// same partial-store contract because TMapDialog's clamp reads the full dword while its
// centering helpers read the signed low word.
// FUNCTION: IMPERIALISM 0x00519970
void InitializeMapDialogViewportTileSpan() {
  short viewportTileSpan = static_cast<short>(g_mapCellRowScale_006a3360 * 512.0 - -1.0);
  memcpy(&g_wMapDialogViewportTileSpan, &viewportTileSpan, sizeof(viewportTileSpan));
}

static int g_mapDialogViewportTileSpanInitializer = (InitializeMapDialogViewportTileSpan(), 0);

// SYNTHETIC: IMPERIALISM 0x005199c0
// TMapDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x00519b30
// TMapDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapDialog, TWorldView)

// Zero the marker/overlay state, center the view on the map's current tile (splitting
// g_pGlobalMapState->field6 into row/col and dispatching the coordinate update virtually —
// the vptr is already TMapDialog's), then seed the scroll/zoom words (previewSquareRadius = 0x40 tile
// pixel size). The split writes only the low words of the two locals, so they are ints whose
// addresses pass as short* (the high words are dead), matching the original stack reads.
// FUNCTION: IMPERIALISM 0x00519b50
TMapDialog::TMapDialog() : TWorldView() {
  int row;
  int col;
  viewportOrigin.x = 0;
  suppressMarkerOverlay34C = false;
  overlayObject35C = 0;
  viewportOrigin.y = 0;
  SplitTileIndexToRowAndColumn(g_pGlobalMapState->field6, reinterpret_cast<short*>(&row),
                               reinterpret_cast<short*>(&col));
  SetMapViewCellCoordinates(col, row);
  unresolvedWord354 = 0;
  selectedTileIndex356 = -1;
  unresolvedFlag358 = false;
  projectionScale = 1;
  previewSquareRadius = 0x40;
  tileDebugOverlayEnabled360 = false;
}

// SYNTHETIC: IMPERIALISM 0x00519c40
// TMapDialog::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00519c70
TMapDialog::~TMapDialog() {}

// FUNCTION: IMPERIALISM 0x00519c90
void TMapDialog::Free() {
  if (quickDrawSurface350 != 0) {
    g_pDisplayMgr->RemoveGWorld(quickDrawSurface350);
    quickDrawSurface350 = 0;
  }
  if (g_pCitySiteCachedPrimaryRenderSurfaceContext != 0 &&
      g_pCitySiteCachedPrimaryRenderSurfaceContext != g_pPrimaryRenderSurfaceContext) {
    g_pDisplayMgr->RemoveGWorld(g_pCitySiteCachedPrimaryRenderSurfaceContext);
    g_pCitySiteCachedPrimaryRenderSurfaceContext = 0;
  }
  if (overlayObject35C != 0) {
    overlayObject35C->Free();
  }
  overlayObject35C = 0;
  TView::Free();
  g_pUiAnimator->FreeUiTransientRegistryPayloads();
}

// FUNCTION: IMPERIALISM 0x00519d30
void TMapDialog::DoPostCreate(int arg) {
  TWorldView::DoPostCreate(arg);

  projectionScale = 1;
  previewSquareRadius = 0x40;

  RECT surfaceBounds = {0, 0, 0x1680, 0x40};
  g_pDisplayMgr->MakeNewGWorld(quickDrawSurface350, 8, surfaceBounds);

  ResetAllTileMarkersToSentinel();

  g_pCitySiteCachedPrimaryRenderSurfaceContext = g_pPrimaryRenderSurfaceContext;
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagDialog);
}

// FUNCTION: IMPERIALISM 0x00519e00
void TMapDialog::RenderStrategicTileSelectionAndNeighborHighlights() {
  short neighborTiles[6] = {-1, -1, -1, -1, -1, -1};
  bool updateNeighborHighlights = false;
  bool frameHoveredTile = cursorId4e != 0xffff && cursorId4e != 0x3f0;
  short activeUnitCategory = static_cast<TMapUberPicture*>(ownerContext)->activeUnitCategoryIndex96;

  if (activeUnitCategory != 0 && activeUnitCategory != 3 && activeUnitCategory != 5) {
    return;
  }

  short hoveredTile = static_cast<short>(hoveredTileIndex);
  if (cursorId4e == 0x3eb) {
    TCivUnit* selectedOrder = g_pSelectedCivilianOrderState->selectedEntry;
    CivilianUnitKindStorage unitKind =
        selectedOrder != 0 ? selectedOrder->orderType : kCivilianUnitKindCount;
    if (unitKind == EncodeCivilianUnitKind(kCivilianUnitEngineer) &&
        g_pGlobalMapState->terrainStateTable[hoveredTile].regionSubtypeTag05 == -1) {
      updateNeighborHighlights = true;
      TMapMgr::GetNeighborTileIDArray(hoveredTile, neighborTiles,
                                      g_pGlobalMapState->hexNeighborWrapHorizontally);
      short activeNation = g_pSimMgr->GetActiveNationId();
      for (int i = 0; i < 6; ++i) {
        short neighbor = neighborTiles[i];
        if (neighbor != -1) {
          const TTerrainStateRecord& neighborState = g_pGlobalMapState->terrainStateTable[neighbor];
          if ((neighborState.ownerNationTag04 != activeNation &&
               neighborState.GetTerrainKind() != kStrategicTerrainWater) ||
              neighborState.regionSubtypeTag05 != -1) {
            neighborTiles[i] = -1;
          }
        }
      }
    }
  }

  short paintedTile = static_cast<short>(paintedHoverTileIndex);
  signed char paintedMarker = g_pGlobalMapState->terrainStateTable[paintedTile].markerSlotIndex10;
  if (paintedMarker != -1 && tileMarkers7c[paintedMarker].flag != 0) {
    short projectedY;
    short projectedX;
    ProjectTileIndexToWrappedScreenOffsetByScale(paintedTile, &viewportOrigin, &projectedY,
                                                 &projectedX, 1);
    CRect sourceRect(projectedX + 0x40, projectedY + 0x40, projectedX + 0x80, projectedY + 0x80);
    CRect destinationRect(projectedX, projectedY, projectedX + 0x40, projectedY + 0x40);
    BlitRectWithOptionalTransparency(g_pCitySiteCachedPrimaryRenderSurfaceContext->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect, &destinationRect, 0, 0);
  }

  for (int i = 0; i < 6; ++i) {
    short oldNeighbor = g_aStrategicMapNeighborHighlightTiles_00697310[i];
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
    CRect sourceRect(projectedX + 0x40, projectedY + 0x40, projectedX + 0x80, projectedY + 0x80);
    CRect destinationRect(projectedX, projectedY, projectedX + 0x40, projectedY + 0x40);
    BlitRectWithOptionalTransparency(g_pCitySiteCachedPrimaryRenderSurfaceContext->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect, &destinationRect, 0, 0);
  }

  if (frameHoveredTile ||
      ((GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0 && g_bRandomMapDeveloperCheatFlag != 0) ||
      activeUnitCategory == 5) {
    short projectedY;
    short projectedX;
    ProjectTileIndexToWrappedScreenOffsetByScale(hoveredTile, &viewportOrigin, &projectedY,
                                                 &projectedX, 1);
    CRect hoveredRect(projectedX, projectedY, projectedX + 0x40, projectedY + 0x40);
    g_pViewMgr->ApplyLegendSplitSlot34(0x3f);
    QDFrameRect(&hoveredRect);
    SetQuickDrawFillColor(0);
    if (updateNeighborHighlights) {
      DrawHexNeighborOutlineFromTileArray(neighborTiles);
    }
  }

  for (int cacheIndex = 0; cacheIndex < 6; ++cacheIndex) {
    g_aStrategicMapNeighborHighlightTiles_00697310[cacheIndex] =
        updateNeighborHighlights ? neighborTiles[cacheIndex] : -1;
  }
}

// Draw the selection outline around a hex tile: for each of the six neighbor
// tiles (neighborTiles[0..5], -1 = none), project it to screen and stroke the
// shared hex-cell edges, skipping an interior edge when the adjacent neighbor is
// also present so shared borders are drawn once. 0x3f is the cell size, 0x20 the
// half-cell.
// FUNCTION: IMPERIALISM 0x0051a2a0
void TMapDialog::DrawHexNeighborOutlineFromTileArray(short* neighborTiles) {
  const CPoint* viewOrigin = &viewportOrigin;
  short outY;
  short outX;

  g_pViewMgr->ApplyLegendSplitSlot34(0x3f);

  if (neighborTiles[0] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[0], viewOrigin, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX, outY);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    if (neighborTiles[5] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY);
      DrawCenteredGuideLineOnMapDc(outX, outY + 0x3f);
    }
    if (neighborTiles[1] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x20, outY + 0x3f);
    }
  }
  if (neighborTiles[1] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[1], viewOrigin, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX + 0x20, outY + 0x3f);
    if (neighborTiles[0] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x20, outY);
    }
    if (neighborTiles[2] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY + 0x3f);
      DrawCenteredGuideLineOnMapDc(outX + 0x20, outY + 0x3f);
    }
  }
  if (neighborTiles[2] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[2], viewOrigin, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    if (neighborTiles[3] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY);
      DrawCenteredGuideLineOnMapDc(outX, outY + 0x3f);
    }
    if (neighborTiles[1] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    }
  }
  if (neighborTiles[3] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[3], viewOrigin, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX + 0x3f, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX, outY);
    if (neighborTiles[2] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x3f, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    }
    if (neighborTiles[4] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x20, outY);
    }
  }
  if (neighborTiles[4] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[4], viewOrigin, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY);
    DrawCenteredGuideLineOnMapDc(outX, outY);
    DrawCenteredGuideLineOnMapDc(outX, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX + 0x20, outY + 0x3f);
    if (neighborTiles[5] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    }
    if (neighborTiles[3] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY + 0x3f);
      DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    }
  }
  if (neighborTiles[5] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[5], viewOrigin, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX, outY);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    if (neighborTiles[0] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x3f, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    }
    if (neighborTiles[4] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY + 0x3f);
      DrawCenteredGuideLineOnMapDc(outX + 0x20, outY + 0x3f);
    }
  }
  SetQuickDrawFillColor(0);
}

// FUNCTION: IMPERIALISM 0x0051a900
void TMapDialog::InvalidateTile(short tileIndex) {
  int originalTileIndex = tileIndex;
  short projectedY;
  ProjectTileIndexToWrappedScreenOffsetByScale(static_cast<short>(originalTileIndex),
                                               &viewportOrigin, &projectedY, &tileIndex, 1);

  CRect invalidateRect(static_cast<short>(tileIndex), projectedY,
                       static_cast<short>(tileIndex) + 0x40, projectedY + 0x40);
  ReleaseTileMarkerForTile(static_cast<short>(originalTileIndex));
  InvalidateCityDialogRectRegion(&invalidateRect, 1);
}

// FUNCTION: IMPERIALISM 0x0051a990
void TMapDialog::ConvertPoint(const CPoint& point, short& outRow, short& outCol, short& outBand) {
  outCol = static_cast<short>(
      static_cast<int>((viewportOrigin.y + point.y) * g_mapCellColumnScale_006a3388));
  short rowValue;
  if ((outCol & 1) != 0) {
    rowValue = static_cast<short>(
        static_cast<int>((point.x + viewportOrigin.x + 0x20) * g_mapCellRowScale_006a3360));
    --rowValue;
  } else {
    rowValue = static_cast<short>(
        static_cast<int>((point.x + viewportOrigin.x) * g_mapCellRowScale_006a3360));
  }
  outRow = rowValue;
  NormalizeWrappedMapCoord108x60(&outRow, &outCol);

  int wrappedY = viewportOrigin.y + point.y;
  short bandRow = static_cast<short>(wrappedY % 0x40);

  short bandCol = 0;
  if ((outCol & 1) != 0) {
    int wrappedX = point.x + 0x20 + viewportOrigin.x;
    bandCol = static_cast<short>(wrappedX % 0x40 - 1);
  } else {
    int wrappedX = point.x + viewportOrigin.x;
    bandCol = static_cast<short>(wrappedX % 0x40);
  }

  if (bandCol < 0x20) {
    outBand = static_cast<short>((bandRow < 0x20) + 1);
    return;
  }
  outBand = static_cast<short>((bandRow >= 0x20) + 3);
}

// FUNCTION: IMPERIALISM 0x0051aad0
void TMapDialog::RefreshMapTile(short tileIndex) {
  PrepareForDrawing();
  ReleaseTileMarkerForTile(tileIndex);

  short projectedY;
  short projectedX;
  ProjectTileIndexToWrappedScreenOffsetByScale(tileIndex, &viewportOrigin, &projectedY, &projectedX,
                                               1);
  if (projectedY > -0x40 && projectedX > -0x40 && projectedX < 0x200 && projectedY < 0x1c0) {
    InvalidateTile(tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x0051ab60
unsigned char TMapDialog::IsTileVisible(short tileIndex) {
  short projectedY;
  short projectedX;
  ProjectTileIndexToWrappedScreenOffsetByScale(tileIndex, &viewportOrigin, &projectedY, &projectedX,
                                               1);
  SetGlobalQuickDrawOrigin(static_cast<short>(absoluteX), static_cast<short>(absoluteY));

  CRect tileRect(projectedX, projectedY, projectedX + 0x40, projectedY + 0x40);
  CRect contentBounds;
  QueryContentBounds(&contentBounds);
  CRect drawableBounds = ViewToQDRect(&contentBounds);
  SectRect(&tileRect, &drawableBounds, &tileRect);
  return ProbeRectEmptyAfterCopyToLocal(&tileRect) == 0;
}

// Centers the map view on the given tile (column offset by half the viewport tile span,
// row offset by 3) and invalidates the whole 0x200x0x1c0 dialog surface.
// FUNCTION: IMPERIALISM 0x0051ac40
void TMapDialog::CenterOn(int tileIndex) {
  int col;
  SplitTileIndexToRowAndColumn(static_cast<short>(tileIndex), reinterpret_cast<short*>(&tileIndex),
                               reinterpret_cast<short*>(&col));
  SetMapViewCellCoordinates(col - static_cast<short>(g_wMapDialogViewportTileSpan) / 2,
                            tileIndex - 3);
  RECT invalidateRect;
  invalidateRect.left = 0;
  invalidateRect.top = 0;
  invalidateRect.right = 0x1ff;
  invalidateRect.bottom = 0x1bf;
  InvalidateCityDialogRectRegion(&invalidateRect, 1);
}

// FUNCTION: IMPERIALISM 0x0051ace0
int TMapDialog::GetCenterTile() const {
  int col = viewportOrigin.x / 0x40 + static_cast<short>(g_wMapDialogViewportTileSpan) / 2;
  int row = viewportOrigin.y / 0x40 + 4;
  NormalizeWrappedMapCoord108x60(reinterpret_cast<short*>(&col), reinterpret_cast<short*>(&row));
  return col + row * 0x6c;
}

// FUNCTION: IMPERIALISM 0x0051ad70
void TMapDialog::SetMapViewTileIndex(int arg1) {
  int tileCol;
  SplitTileIndexToRowAndColumn(static_cast<short>(arg1), reinterpret_cast<short*>(&arg1),
                               reinterpret_cast<short*>(&tileCol));
  SetMapViewCellCoordinates(tileCol, arg1);
}

// FUNCTION: IMPERIALISM 0x0051adc0
void TMapDialog::SetMapViewCellCoordinates(int column, int row) {
  SetMapDialogCellCoordinatesAndRefresh(column, row, 0);
}

// Clamps/wraps the requested viewport cell (108x54 tile map, viewport span from
// g_wMapDialogViewportTileSpan when horizontal wrap is off), commits the new viewport
// offsets (Y before X, matching the original store order), records the new center tile
// in g_pGlobalMapState->field6, invalidates the dialog surface, refreshes the owning
// uber-picture's mini-map, and translates/prunes the transient animation rects.
// `mode` is dead in this implementation (the slot's convention keeps it; TCitySiteView's
// override forwards it here unchanged, and all known call sites pass 0).
// FUNCTION: IMPERIALISM 0x0051adf0
void TMapDialog::SetMapDialogCellCoordinatesAndRefresh(int col, int row, int mode) {
  (void)mode;
  if (g_pGlobalMapState->hexNeighborWrapHorizontally != 0) {
    int span = g_wMapDialogViewportTileSpan;
    if (static_cast<short>(col) > 0x6e - static_cast<short>(span)) {
      col = 0x6e - span;
    } else if (static_cast<short>(col) < 1) {
      col = 1;
    }
  }
  if (static_cast<short>(col) < 0) {
    col = col + 0x6c;
  } else if (static_cast<short>(col) >= 0x6c) {
    col = col - 0x6c;
  }
  if (static_cast<short>(row) < 0) {
    row = 0;
  } else if (static_cast<short>(row) > 0x35) {
    row = 0x35;
  }

  int oldY = viewportOrigin.y;
  int oldX = viewportOrigin.x;
  viewportOrigin.y = static_cast<short>(row) << 6;
  viewportOrigin.x = static_cast<short>(col) << 6;

  g_pGlobalMapState->field6 = static_cast<short>(ComputeStridedRecordAddress6C(col, row));

  if (ownerContext != 0) {
    RECT rect;
    rect.left = 0;
    rect.top = 0;
    rect.right = 0x200;
    rect.bottom = 0x1c0;
    InvalidateCityDialogRectRegion(&rect, 1);
    static_cast<TMapUberPicture*>(ownerContext)->InvalidateMiniMap();
  }
  int dx = oldX - viewportOrigin.x;
  int dy = oldY - viewportOrigin.y;
  RECT clip;
  clip.left = -0x40;
  clip.top = -0x40;
  clip.right = 0x240;
  clip.bottom = 0x200;
  g_pUiAnimator->TranslateListRectsAndDropNonIntersectingEntries(dx, dy, clip);
}

// FUNCTION: IMPERIALISM 0x0051af60
void TMapDialog::UpdateMapInteractionPreviewParityAndRenderTransientSprites(int edgeMask) {
  short col;
  short row;
  short regionBand;
  ConvertPoint(g_MapInteractionPreviewPoint_006a3370, col, row, regionBand);

  if ((row & 1) != 0) {
    ++col;
    if (col >= 108) {
      col = 0;
    }
  }

  bool useHalfCellCoordinates = g_pSimMgr->preferenceValues[12] != 0;
  int adjustedRow = row;
  int adjustedCol = col;
  if (useHalfCellCoordinates) {
    adjustedRow = g_MapInteractionPreviewRowParity_006a33b4 + row * 2;
    adjustedCol = g_MapInteractionPreviewColumnParity_006a33b8 + col * 2;
  }

  if ((edgeMask & 1) != 0) {
    --adjustedRow;
  } else if ((edgeMask & 2) != 0) {
    ++adjustedRow;
  }
  if ((edgeMask & 4) != 0) {
    ++adjustedCol;
  } else if ((edgeMask & 8) != 0) {
    --adjustedCol;
  }

  if (useHalfCellCoordinates) {
    g_MapInteractionPreviewRowParity_006a33b4 = adjustedRow & 1;
    g_MapInteractionPreviewColumnParity_006a33b8 = adjustedCol & 1;
    adjustedRow >>= 1;
    adjustedCol >>= 1;
  } else {
    g_MapInteractionPreviewRowParity_006a33b4 = 0;
    g_MapInteractionPreviewColumnParity_006a33b8 = 0;
  }

  SetMapDialogCellCoordinatesAndRefresh(adjustedCol, adjustedRow, 1);
  g_pDisplayMgr->activeDialog->ForceRedraw();
}

// FUNCTION: IMPERIALISM 0x0051b1c0
void TMapDialog::PopulateMapContextInfoPanelStringsByTileSelection(short tileIndex, int unusedArg) {
  (void)unusedArg;
  CString mainText;
  CString numberText;
  CString nameText;
  CString cityName;

  TView* titleControl = ResolveControlByTag(kControlTagTitl); // 'titl'
  if (titleControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMapDlog_006973D0, 0x459);
  }
  g_pSimMgr->GetString(0x1cb7, g_pGlobalMapState->terrainStateTable[tileIndex].GetTerrainKind(),
                       &mainText);
  numberText.Format(g_szDecimalFormat, tileIndex);
  mainText += " (#" + numberText + g_szUiCloseParen_006973C8;
  static_cast<TStaticText*>(titleControl)->SetTextAndMaybeRefresh(&mainText, 1);

  TView* infoControl = ResolveControlByTag(kControlTagInfo); // 'info'
  if (infoControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMapDlog_006973D0, 0x463);
  }
  mainText = CString(g_szEmptyString);

  TView* locationControl;
  short cityIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
  if (cityIndex != -1) {
    if (g_pGlobalMapState->cityScoreTable[cityIndex].cityTileIndex04 == tileIndex) {
      if (g_pGlobalMapState->terrainStateTable[tileIndex].activeFlags1c & 1) {
        mainText += "National Capitol\n";
      } else {
        mainText += "Province Capitol\n";
      }
      for (short resourceType = kResourceManufacturedFirst;
           resourceType <= kResourceManufacturedLast; resourceType++) {
        short count = g_pGlobalMapState->cityScoreTable[cityIndex]
                          .resourceDevelopmentCounts82[resourceType - 7];
        if (count != 0) {
          numberText.Format(g_szDecimalFormat, count);
          g_pSimMgr->GetString(0x2711, resourceType, &nameText);
          mainText += numberText + " " + nameText + "\n";
        }
      }
    }
    for (int edge = 0; edge < 2; edge++) {
      short resourceType = g_pGlobalMapState->terrainStateTable[tileIndex].resourceTypeByEdge[edge];
      if (resourceType != -1) {
        g_pSimMgr->GetString(0x2711, resourceType, &nameText);
        numberText.Format(
            g_szDecimalFormat,
            static_cast<signed char>(
                g_pGlobalMapState->FindResourceCapabilityRequirementLevel(tileIndex, edge)));
        mainText += numberText + " " + nameText + "\n";
      }
    }
    static_cast<TStaticText*>(infoControl)->SetTextAndMaybeRefresh(&mainText, 1);

    g_pGlobalMapState->AssignCityRecordDisplayName(cityIndex, &cityName);
    TCountry* owner = g_apTerrainTypeDescriptorTable[g_pGlobalMapState->terrainStateTable[tileIndex]
                                                         .ownerNationTag04];
    if (owner != 0 && owner->encodedNationSlot >= 0x64 && owner->encodedNationSlot < 0xc8) {
      static_cast<TGreatPower*>(owner)->LoadNationDisplayNameSharedRefFromField8(&nameText);
    } else {
      // The original invokes this on the table entry even when it is null.
      owner->FormatOverlayTerrainLabelText(&nameText);
    }
    mainText = cityName + ", " + nameText;

    int currentOwner =
        static_cast<char>(g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04);
    int formerOwner =
        static_cast<char>(g_pGlobalMapState->terrainStateTable[tileIndex].formerOwnerNationTag03);
    if (currentOwner != formerOwner) {
      if (formerOwner >= 0 && formerOwner <= 0x17 &&
          g_apTerrainTypeDescriptorTable[formerOwner] != 0) {
        static_cast<TGreatPower*>(g_apTerrainTypeDescriptorTable[formerOwner])
            ->LoadNationDisplayNameSharedRefFromField8(&nameText);
      } else {
        nameText.Format(g_szDecimalFormat, formerOwner);
        nameText = "#" + nameText;
      }
      mainText = mainText + " (formerly of " + nameText + g_szUiCloseParen_006973C8;
    }
    locationControl = ResolveControlByTag(kControlTagLoca); // 'loca'
    if (locationControl == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMapDlog_006973D0, 0x4a3);
    }
  } else {
    TZone* zone = g_pActiveMapOrderContext->GetMapActionContextEntryByNationCodeOffset17(
        g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04);
    zone->AssignZoneDisplayNameToOutputRef(&mainText);
    locationControl = ResolveControlByTag(kControlTagLoca); // 'loca'
    if (locationControl == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMapDlog_006973D0, 0x4ab);
    }
  }
  static_cast<TStaticText*>(locationControl)->SetTextAndMaybeRefresh(&mainText, 1);
}

// FUNCTION: IMPERIALISM 0x0051e0b0
void InitializeMapInteractionPreviewScaleXDefault() {
  g_MapPreviewScaleX6A3410 = 0.015625;
}

// FUNCTION: IMPERIALISM 0x0051e0e0
void InitializeMapInteractionPreviewScaleYDefault() {
  g_MapPreviewScaleY6A33D0 = 0.015625;
}

// FUNCTION: IMPERIALISM 0x0051e110
void RecomputeMapInteractionPreviewVerticalOffsetFromScale() {
  g_MapPreviewVerticalOffset6A3448 = static_cast<short>(g_MapPreviewScaleY6A33D0 * 512.0 - -1.0);
}

// FUNCTION: IMPERIALISM 0x0051e1a0
void TMapDialog::ResetAllTileMarkersToSentinel() {
  g_pGlobalMapState->ResetAllTileMarkerSlotIndicesToSentinel();
  for (int i = 0; i < 90; i++) {
    tileMarkers7c[i].flag = 0;
    tileMarkers7c[i].a = -1;
    tileMarkers7c[i].b = -1;
    tileMarkers7c[i].c = -1;
  }
}

// FUNCTION: IMPERIALISM 0x0051e1f0
void TMapDialog::ReleaseTileMarkerForTile(short tileIndex) {
  // Architecturally complete; the residual vs the original is MSVC hoisting the shared -1
  // sentinel into a callee-saved register (bl/bx/ebx) rather than immediates.
  short slot = g_pGlobalMapState->terrainStateTable[tileIndex].markerSlotIndex10;
  if (slot != -1) {
    g_pGlobalMapState->terrainStateTable[tileIndex].markerSlotIndex10 = -1;
    tileMarkers7c[slot].flag = 0;
    tileMarkers7c[slot].a = -1;
    tileMarkers7c[slot].b = -1;
    tileMarkers7c[slot].c = -1;
  }
}

// FUNCTION: IMPERIALISM 0x0051e260
void TMapDialog::Draw(RECT* rectBuffer) {
  if (g_pGlobalMapState == 0) {
    return;
  }

  CTemporaryRegion savedClip;
  RECT dirtyRect = *rectBuffer;
  RECT cacheRect = dirtyRect;
  static CSize cacheMargin(0x40, 0x40);
  OffsetRect(&cacheRect, cacheMargin.cx, cacheMargin.cy);

  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags = 0;
  GetClip(savedClip.tempRgn);
  GetGWorld(&savedSurface, &savedSurfaceFlags);

  if (!suppressMarkerOverlay34C) {
    ResetQuickDrawStrokeState();
    SetGWorld(quickDrawSurface350, savedSurfaceFlags);
    LockPixels(GetGWorldPixMap(g_pCitySiteCachedPrimaryRenderSurfaceContext));
    LockPixels(GetGWorldPixMap(quickDrawSurface350));

    int markerFirstRow = static_cast<int>(viewportOrigin.y * g_MapPreviewScaleX6A3410);
    int markerFirstCol = static_cast<int>(viewportOrigin.x * g_MapPreviewScaleY6A33D0 - 1.0);
    int markerLastCol = markerFirstCol + g_MapPreviewVerticalOffset6A3448;

    int markerIndex;
    for (markerIndex = 0; markerIndex < 90; ++markerIndex) {
      TMapDialogTileMarker& marker = tileMarkers7c[markerIndex];
      marker.flag = marker.a >= markerFirstRow && marker.a <= markerFirstRow + 8 &&
                    marker.b >= markerFirstCol && marker.b <= markerLastCol;
    }

    int firstRowValue = viewportOrigin.y + rectBuffer->top;
    short firstRow = static_cast<short>(DivideMapPixelOffsetBy64(firstRowValue));
    int rowSpan = rectBuffer->bottom - rectBuffer->top;
    short lastRow = static_cast<short>(firstRow + DivideMapPixelOffsetBy64(rowSpan) + 1);
    int firstColValue = viewportOrigin.x + rectBuffer->left + 0x20;
    short firstCol = static_cast<short>(DivideMapPixelOffsetBy64(firstColValue) - 1);
    int colSpan = rectBuffer->right - rectBuffer->left;
    short lastCol = static_cast<short>(firstCol + DivideMapPixelOffsetBy64(colSpan) + 1);

    GetPixBaseAddr(GetGWorldPixMap(quickDrawSurface350));
    GetPixBaseAddr(GetGWorldPixMap(g_pCitySiteCachedPrimaryRenderSurfaceContext));
    GetPixBaseAddr(GetGWorldPixMap(g_pMacViewMgr->atlas668));

    short cacheSearchIndex = 0;
    for (short row = firstRow; row < lastRow && row < 60; ++row) {
      for (short unwrappedCol = firstCol; unwrappedCol <= lastCol; ++unwrappedCol) {
        short col = unwrappedCol;
        if (col >= 108) {
          col -= 108;
        } else if (col < 0) {
          col += 108;
        }

        short tileIndex =
            static_cast<short>(ComputeStridedRecordAddress6C(static_cast<int>(col), row));
        short projectedY;
        short projectedX;
        ProjectTileIndexToWrappedScreenOffsetByScale(tileIndex, &viewportOrigin, &projectedY,
                                                     &projectedX, 1);
        if (projectedX >= rectBuffer->right) {
          continue;
        }

        signed char cachedMarkerIndex =
            g_pGlobalMapState->terrainStateTable[tileIndex].markerSlotIndex10;
        if (cachedMarkerIndex == -1) {
          ++g_MapTileCacheMissCount6A3454;
          while (cacheSearchIndex < 90 && tileMarkers7c[cacheSearchIndex].flag != 0) {
            ++cacheSearchIndex;
          }
          TMapDialogTileMarker& marker = tileMarkers7c[cacheSearchIndex];
          if (marker.c >= 0) {
            g_pGlobalMapState->terrainStateTable[marker.c].markerSlotIndex10 = -1;
          }
          marker.flag = 1;
          marker.a = row;
          marker.b = unwrappedCol;
          marker.c = tileIndex;
          g_pGlobalMapState->terrainStateTable[tileIndex].markerSlotIndex10 =
              static_cast<signed char>(cacheSearchIndex);
          DrawOneTile(tileIndex, 0, cacheSearchIndex << 6);
          cachedMarkerIndex = static_cast<signed char>(cacheSearchIndex);
        } else {
          TCivUnit* unit =
              g_pGlobalMapState->GetTileUnitEntryByOwner(tileIndex, g_pSimMgr->GetActiveNationId());
          int animationTag = PointerAddressLong32(unit);
          if (unit != 0 && unit->unitOrder > static_cast<UnitOrder>(4) &&
              g_pUiAnimator->FindRegisteredAnimationByTag(animationTag) == 0) {
            short animationY;
            short animationX;
            ProjectTileIndexToWrappedScreenOffsetByScale(tileIndex, &viewportOrigin, &animationY,
                                                         &animationX, 1);
            RECT animationRect = {animationX, animationY, animationX + 0x40, animationY + 0x40};
            TCivAnimation2* animation =
                new TCivAnimation2(this, &animationRect, unit->orderType, animationTag);
            g_pUiAnimator->AddObjectToUiTransientRegistry(animation);
          }
        }

        RECT sourceRect;
        sourceRect.left = static_cast<long>(cachedMarkerIndex) << 6;
        sourceRect.top = 0;
        sourceRect.right = sourceRect.left + 0x40;
        sourceRect.bottom = 0x40;
        RECT destinationRect;
        destinationRect.left = projectedX + 0x40;
        destinationRect.top = projectedY + 0x40;
        destinationRect.right = destinationRect.left + 0x40;
        destinationRect.bottom = destinationRect.top + 0x40;
        quickDrawSurface350->GetBlitSurface()->surfaceDib->BlitSurfaceRectSkippingTransparentColor(
            g_pCitySiteCachedPrimaryRenderSurfaceContext->GetBlitSurface()->surfaceDib,
            sourceRect.left, sourceRect.top, sourceRect.right - sourceRect.left,
            sourceRect.bottom - sourceRect.top, destinationRect.left, destinationRect.top, -1);

        TCivUnit* firstCivilianOrder =
            g_pGlobalMapState->terrainStateTable[tileIndex].firstCivilianOrder20;
        if (firstCivilianOrder != 0) {
          TAnimation* animation =
              g_pUiAnimator->FindRegisteredAnimationByTag(PointerAddressLong32(firstCivilianOrder));
          if (animation != 0) {
            SetGWorld(g_pCitySiteCachedPrimaryRenderSurfaceContext, savedSurfaceFlags);
            RECT animationClip = animation->screenRect;
            OffsetRect(&animationClip, 0x40, 0x40);
            ClipRect(&animationClip);
            POINT drawOffset = {0x40, 0x40};
            animation->DrawNextFrame(&drawOffset);
            SetGWorld(quickDrawSurface350, savedSurfaceFlags);
          }
        }
      }
    }

    SetGWorld(g_pCitySiteCachedPrimaryRenderSurfaceContext, savedSurfaceFlags);
    RECT overlayClip = cacheRect;
    overlayClip.right += 0x80;
    overlayClip.bottom += 0x80;
    ClipRect(&overlayClip);
    DrawGeneratedMapRouteSegmentsAndResetFillColor();
    ResetQuickDrawStrokeState();
    SetGWorld(savedSurface, savedSurfaceFlags);
    SetClip(savedClip.tempRgn);
  }

  OffsetRect(&cacheRect, g_MapInteractionPreviewColumnParity_006a33b8 << 5,
             g_MapInteractionPreviewRowParity_006a33b4 << 5);
  BlitRectWithOptionalTransparency(g_pCitySiteCachedPrimaryRenderSurfaceContext->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &cacheRect,
                                   &dirtyRect, 0, 0);
  UnlockPixels(GetGWorldPixMap(g_pCitySiteCachedPrimaryRenderSurfaceContext));
  UnlockPixels(GetGWorldPixMap(quickDrawSurface350));
}

// FUNCTION: IMPERIALISM 0x0051eb40
void TMapDialog::DrawOneTile(short tileIndex, short screenY, short screenX) {
  CTemporaryRegion temporaryRegion;
  TBitmapSurfaceNode** destinationSurfaceObject = GetGWorldPixMap(quickDrawSurface350);
  unsigned char* destinationPixels = GetPixBaseAddr(destinationSurfaceObject);
  short destinationStride = static_cast<short>((*destinationSurfaceObject)->stride & 0x3fff);
  destinationPixels += static_cast<int>(screenY) * destinationStride + screenX;

  TBitmapSurfaceNode** sourceSurfaceObject = GetGWorldPixMap(g_pMacViewMgr->atlas668);
  unsigned char* sourcePixels = GetPixBaseAddr(sourceSurfaceObject);
  short sourceStride = static_cast<short>((*sourceSurfaceObject)->stride & 0x3fff);

  const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[tileIndex];
  const bool isOcean = terrain.GetTerrainKind() == kStrategicTerrainWater;
  bool usedWrappedSeamTile = false;
  if (g_pGlobalMapState->hexNeighborWrapHorizontally != 0) {
    int tileColumn = tileIndex % 108;
    short centerTile = static_cast<short>(GetCenterTile());
    int centerColumn = centerTile % 108;
    if ((tileColumn == 0 && centerColumn > 54) || (tileColumn == 107 && centerColumn < 54)) {
      short seamOffset = g_pGlobalMapState->GetFixedConstant0xc80();
      NewCopy64(sourcePixels + seamOffset, destinationPixels, sourceStride, destinationStride);
      usedWrappedSeamTile = true;
    }
  }

  if (!usedWrappedSeamTile) {
    short sourceOffset;
    if (isOcean) {
      sourceOffset = g_pGlobalMapState->LookupTileSpriteVariantOffsetByAdjacencyMaskB(tileIndex);
    } else {
      sourceOffset = g_pGlobalMapState->LookupTileSpriteVariantOffsetByTerrainAndGate(tileIndex);
    }

    NewCopy64(sourcePixels + sourceOffset, destinationPixels, sourceStride, destinationStride);

    if (!isOcean) {
      for (int direction = 0; direction < 6; ++direction) {
        int directionBit = 1 << direction;
        unsigned char* transitionSource = 0;
        if ((terrain.adjacencyMaskA0a & directionBit) != 0) {
          transitionSource =
              sourcePixels +
              g_pGlobalMapState->LookupTileSpriteVariantOffsetByGateAndVariant(tileIndex);
        } else if ((terrain.adjacencyMaskB0b & directionBit) != 0 &&
                   terrain.GetTerrainKind() != kStrategicTerrainDesert) {
          transitionSource =
              sourcePixels +
              g_pGlobalMapState->LookupTileSpriteVariantOffsetByGateAndVariantAlt(tileIndex);
        }

        if (transitionSource != 0) {
          switch (direction) {
          case 0:
            CopyTerrainTransitionMaskDirection0(transitionSource, destinationPixels, sourceStride,
                                                destinationStride);
            break;
          case 1:
            CopyTerrainTransitionMaskDirection1(transitionSource, destinationPixels, sourceStride,
                                                destinationStride);
            break;
          case 2:
            CopyTerrainTransitionMaskDirection2(transitionSource, destinationPixels, sourceStride,
                                                destinationStride);
            break;
          case 3:
            CopyTerrainTransitionMaskDirection3(transitionSource, destinationPixels, sourceStride,
                                                destinationStride);
            break;
          case 4:
            CopyTerrainTransitionMaskDirection4(transitionSource, destinationPixels, sourceStride,
                                                destinationStride);
            break;
          case 5:
            CopyTerrainTransitionMaskDirection5(transitionSource, destinationPixels, sourceStride,
                                                destinationStride);
            break;
          }
        }
      }
    }

    if (isOcean && terrain.adjacencyMaskB0b != 0) {
      const unsigned char adjacencyMask = terrain.adjacencyMaskB0b;
      const unsigned char variantMask = terrain.spriteVariantIndex01;
      const short riverSpriteCode = terrain.riverSpriteCode;
      for (int corner = 0; corner < 6; ++corner) {
        int previousDirection = (corner + 5) % 6;
        int cornerBits = (1 << previousDirection) | (1 << corner);
        if ((adjacencyMask & cornerBits) == 0) {
          continue;
        }

        bool useTripleOffset = false;
        switch (corner) {
        case 1:
          useTripleOffset = riverSpriteCode == kRiverSpriteCodeWaterSingleDirectionFirst ||
                            riverSpriteCode == kRiverSpriteCodeWaterSingleDirectionFirst + 1;
          break;
        case 2:
          useTripleOffset = riverSpriteCode == kRiverSpriteCodeWaterSingleDirectionFirst + 2 ||
                            riverSpriteCode == kRiverSpriteCodeWaterSingleDirectionFirst + 3;
          break;
        case 3:
          useTripleOffset = riverSpriteCode == kRiverSpriteCodeWaterSingleDirectionFirst + 3 ||
                            riverSpriteCode == kRiverSpriteCodeWaterSingleDirectionFirst + 4;
          break;
        case 4:
          useTripleOffset = riverSpriteCode == kRiverSpriteCodeWaterSingleDirectionFirst + 4 ||
                            riverSpriteCode == kRiverSpriteCodeWaterSingleDirectionFirst + 6;
          break;
        case 5:
          useTripleOffset = riverSpriteCode == kRiverSpriteCodeWaterSingleDirectionFirst + 5 ||
                            riverSpriteCode == kRiverSpriteCodeWaterSingleDirectionLast;
          break;
        }
        short coastOffset;
        if (useTripleOffset) {
          coastOffset = g_pGlobalMapState->MapImprovementOffsetFromAdjacencyVariantTriple(
              static_cast<char>(adjacencyMask), static_cast<char>(corner + 1), riverSpriteCode);
        } else {
          coastOffset = g_pGlobalMapState->MapImprovementOffsetFromAdjacencyVariant(
              static_cast<char>(adjacencyMask), static_cast<char>(corner + 1),
              static_cast<char>(variantMask & (1 << corner)));
        }
        if (coastOffset == 0) {
          continue;
        }

        unsigned char* coastSource = sourcePixels + coastOffset;
        switch (corner) {
        case 0:
          CopyCoastCornerMaskBetweenDirections5And0(coastSource, destinationPixels, sourceStride,
                                                    destinationStride);
          break;
        case 1:
          CopyCoastCornerMaskBetweenDirections0And1(coastSource, destinationPixels, sourceStride,
                                                    destinationStride);
          break;
        case 2:
          CopyCoastCornerMaskBetweenDirections1And2(coastSource, destinationPixels, sourceStride,
                                                    destinationStride);
          break;
        case 3:
          CopyCoastCornerMaskBetweenDirections2And3(coastSource, destinationPixels, sourceStride,
                                                    destinationStride);
          break;
        case 4:
          CopyCoastCornerMaskBetweenDirections3And4(coastSource, destinationPixels, sourceStride,
                                                    destinationStride);
          break;
        case 5:
          CopyCoastCornerMaskBetweenDirections4And5(coastSource, destinationPixels, sourceStride,
                                                    destinationStride);
          break;
        }
      }
    }

    if (terrain.riverSpriteCode != kRiverSpriteCodeNone) {
      int normalizedSpriteCode = terrain.riverSpriteCode;
      if (normalizedSpriteCode > kRiverSpriteCodeFlowLast) {
        normalizedSpriteCode -= kRiverSpriteCodeFlowVariantBias;
      }
      StrategicMapCallbackRecord* terrainMask =
          &g_pMacViewMgr->strategicTileMasks6bc[normalizedSpriteCode - kRiverSpriteCodeFlowFirst];
      terrainMask->SetDestinationHeightNoOp(0x40);
      terrainMask->ApplyBitmapMaskToPixelBuffer(destinationPixels);
    }

    if (terrain.ownerBorderMask07 != 0) {
      SetQuickDrawFillColor(0);
      if (!isOcean) {
        SetQuickDrawPenSizeAndMarkDirty(2, 2);
        DrawNationBorderSegmentsByMask(terrain.ownerBorderMask07, screenX, screenY, tileIndex);
      } else {
        SetQuickDrawPenSizeAndMarkDirty(1, 1);
        if (terrain.adjacencyMaskB0b != 0) {
          SetQuickDrawPenSizeAndMarkDirty(2, 2);
          DrawSeaZoneBorders(screenX, screenY, tileIndex);
        }
      }
      SetQuickDrawPenSizeAndMarkDirty(1, 1);
      SetQuickDrawFillColor(0);
    }
    if (!isOcean && terrain.cityBorderMask08 != 0) {
      SetQuickDrawFillColor(0xffffff);
      DrawCityBorderSegmentsByMask(terrain.cityBorderMask08, screenX, screenY, tileIndex);
      SetQuickDrawFillColor(0);
    }
  }

  CRect tileRect;
  tileRect.left = screenX;
  tileRect.top = screenY;
  tileRect.right = screenX + 0x40;
  tileRect.bottom = screenY + 0x40;

  if (terrain.adjacencyMaskA0a != 0 || terrain.adjacencyMaskB0b != 0) {
    for (int direction = 0; direction < 6; ++direction) {
      unsigned char directionBit = static_cast<unsigned char>(1 << direction);
      StrategicMapCallbackRecord* routeMask = 0;
      if ((terrain.adjacencyMaskA0a & directionBit) != 0) {
        routeMask = &g_pMacViewMgr->strategicTileMasks6bc[0x18 + direction];
      } else if ((terrain.adjacencyMaskB0b & directionBit) != 0 &&
                 terrain.GetTerrainKind() != kStrategicTerrainDesert) {
        routeMask = &g_pMacViewMgr->strategicTileMasks6bc[0x1e + direction];
      }
      if (routeMask != 0) {
        routeMask->SetDestinationHeightNoOp(tileRect.bottom - tileRect.top);
        routeMask->ApplyBitmapMaskToPixelBuffer(destinationPixels);
      }
    }
  }

  const unsigned short activeFlags = terrain.activeFlags1c;
  TMapUberPicture* mapOwner = static_cast<TMapUberPicture*>(ownerContext);
  const bool cityOverlayVisible = mapOwner->activeUnitCategoryIndex96 != 4;

  if ((activeFlags & 3) != 0 && terrain.gateFlag != 0 && cityOverlayVisible) {
    int improvementOffset = g_pGlobalMapState->GetMapImprovementOffsetByActiveFlagsAndCityStage(
        tileIndex, terrain.formerOwnerNationTag03);
    Blit64x64StrategicMapAtlasTile(g_pMacViewMgr->atlas66c, quickDrawSurface350, improvementOffset,
                                   tileRect);
  }

  if ((activeFlags & 0x14) != 0 && (activeFlags & 1) == 0) {
    int transportOffset = g_pGlobalMapState->GetMapImprovementOffsetByTownTransportLink(
        tileIndex, terrain.ownerNationTag04);
    if (transportOffset != 0) {
      Blit64x64StrategicMapAtlasTile(g_pMacViewMgr->atlas66c, quickDrawSurface350, transportOffset,
                                     tileRect);
    }
  }

  if ((activeFlags & 3) != 0 && terrain.gateFlag != 0) {
    RenderTacticalStackCountIndicatorAndUnitBadge(tileIndex, &tileRect, 0);
    if (terrain.cityRecordIndex >= 0 && terrain.cityRecordIndex < 0x180) {
      int fortLevel = g_pGlobalMapState->cityScoreTable[terrain.cityRecordIndex].fortLevel03;
      if (fortLevel != 0) {
        int fortOffset = g_pGlobalMapState->GetMapImprovementBitmapRowOffsetForIndex(fortLevel - 1);
        Blit64x64StrategicMapAtlasTile(g_pMacViewMgr->atlas66c, quickDrawSurface350, fortOffset,
                                       tileRect);
      }
    }
  }

  if ((activeFlags & 3) == 0 || terrain.gateFlag == 0) {
    const char lowImprovementClass =
        static_cast<char>(g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(tileIndex, 0));
    const char highImprovementClass =
        static_cast<char>(g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(tileIndex, 1));
    const signed char firstResourceType = terrain.resourceTypeByEdge[0];
    const bool firstResourceIsProspectable =
        firstResourceType == kResourceCoal || firstResourceType == kResourceIron ||
        firstResourceType == kResourceOil || firstResourceType == kResourceGems ||
        firstResourceType == kResourceGold;
    if (firstResourceIsProspectable) {
      if (highImprovementClass != 0) {
        g_pMacViewMgr->DrawStrategicMapUnitIconOverlay(
            destinationSurfaceObject, static_cast<unsigned short>(firstResourceType),
            highImprovementClass, static_cast<short>(screenX + 2), static_cast<short>(screenY + 2));
      } else {
        const int activeNation = g_pSimMgr->GetActiveNationId();
        bool tileVisible = (terrain.pendingDevelopmentFlag0d & (1 << activeNation)) != 0;
        if (!tileVisible && g_pGlobalMapState->field24 != 0) {
          tileVisible = terrain.GetTerrainKind() == kStrategicTerrainHills ||
                        terrain.GetTerrainKind() == kStrategicTerrainMountain ||
                        terrain.GetTerrainKind() == kStrategicTerrainSwamp ||
                        terrain.GetTerrainKind() == kStrategicTerrainDesert;
        }
        if (tileVisible) {
          IMPERIALISM_RUNTIME_OBSERVE_STRATEGIC_RESOURCE(tileIndex, firstResourceType);
          g_pMacViewMgr->DrawStrategicMapUnitIcon(destinationSurfaceObject, firstResourceType,
                                                  screenX, screenY);
        }
      }
    } else {
      if (lowImprovementClass != 0) {
        IMPERIALISM_RUNTIME_OBSERVE_STRATEGIC_IMPROVEMENT(tileIndex, firstResourceType,
                                                          lowImprovementClass);
        g_pMacViewMgr->DrawStrategicMapUnitIconOverlay(
            destinationSurfaceObject, static_cast<unsigned short>(firstResourceType),
            lowImprovementClass, static_cast<short>(screenX + 0x1b),
            static_cast<short>(screenY + 2));
      }
      const int activeNation = g_pSimMgr->GetActiveNationId();
      bool tileVisible = (terrain.pendingDevelopmentFlag0d & (1 << activeNation)) != 0;
      if (!tileVisible && g_pGlobalMapState->field24 != 0) {
        tileVisible = terrain.GetTerrainKind() == kStrategicTerrainHills ||
                      terrain.GetTerrainKind() == kStrategicTerrainMountain ||
                      terrain.GetTerrainKind() == kStrategicTerrainSwamp ||
                      terrain.GetTerrainKind() == kStrategicTerrainDesert;
      }
      TCivUnit* selectedCivilian = g_pSelectedCivilianOrderState->selectedEntry;
      if (tileVisible && selectedCivilian != 0 &&
          (selectedCivilian->orderType == EncodeCivilianUnitKind(kCivilianUnitProspector) ||
           selectedCivilian->orderType == EncodeCivilianUnitKind(kCivilianUnitMiner) ||
           selectedCivilian->orderType == EncodeCivilianUnitKind(kCivilianUnitDeveloper))) {
        UpdatePaletteIndexWithDefaultFallback(0x10);
        SetQuickDrawFillColor(0);
        CRect sourceRect(0x190, 0, 0x1a4, 0x14);
        CRect destinationRect(screenX + 5, screenY + 0xc, screenX + 0x19, screenY + 0x20);
        IMPERIALISM_RUNTIME_OBSERVE_STRATEGIC_SURVEY_MISS(tileIndex);
        BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas694[1]->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &sourceRect, &destinationRect, 0x24, 0);
        SetQuickDrawStrokeColor(0xffffff);
      }
    }

    const signed char secondResourceType = terrain.resourceTypeByEdge[1];
    const bool secondResourceIsProspectable =
        secondResourceType == kResourceCoal || secondResourceType == kResourceIron ||
        secondResourceType == kResourceOil || secondResourceType == kResourceGems ||
        secondResourceType == kResourceGold;
    if (secondResourceIsProspectable) {
      if (highImprovementClass != 0) {
        g_pMacViewMgr->DrawStrategicMapUnitIconOverlay(
            destinationSurfaceObject, static_cast<unsigned short>(secondResourceType),
            highImprovementClass, static_cast<short>(screenX + 2),
            static_cast<short>(screenY + 0x1c));
      } else {
        const int activeNation = g_pSimMgr->GetActiveNationId();
        bool tileVisible = (terrain.pendingDevelopmentFlag0d & (1 << activeNation)) != 0;
        if (!tileVisible && g_pGlobalMapState->field24 != 0) {
          tileVisible = terrain.GetTerrainKind() == kStrategicTerrainHills ||
                        terrain.GetTerrainKind() == kStrategicTerrainMountain ||
                        terrain.GetTerrainKind() == kStrategicTerrainSwamp ||
                        terrain.GetTerrainKind() == kStrategicTerrainDesert;
        }
        if (tileVisible) {
          IMPERIALISM_RUNTIME_OBSERVE_STRATEGIC_RESOURCE(tileIndex, secondResourceType);
          g_pMacViewMgr->DrawStrategicMapUnitIcon(destinationSurfaceObject, secondResourceType,
                                                  screenX, static_cast<short>(screenY + 0x1c));
        }
      }
    }

    if (secondResourceType == kResourceLivestock &&
        (firstResourceType == kResourceCoal || firstResourceType == kResourceIron) &&
        lowImprovementClass != 0) {
      g_pMacViewMgr->DrawStrategicMapUnitIconOverlay(
          destinationSurfaceObject, kResourceLivestock, lowImprovementClass,
          static_cast<short>(screenX + 0x1b), static_cast<short>(screenY + 0x1c));
    }

    if (g_pDiplomacyTurnStateManager->IsGreatPower(terrain.ownerNationTag04) == 0 &&
        terrain.secondaryOwnerNationTag18 != -1) {
      g_pMacViewMgr->BlitStrategicMapUnitActivityOverlayFrame(
          destinationSurfaceObject, terrain.secondaryOwnerNationTag18,
          static_cast<short>(screenX + 0x1e), static_cast<short>(screenY + 0x14));
    }
  }

  if (cityOverlayVisible) {
    short neighborTile =
        TMapMgr::GetNeighborTileID(tileIndex, static_cast<StrategicHexDirectionStorage>(5));
    if (neighborTile != -1) {
      const TTerrainStateRecord& neighbor = g_pGlobalMapState->terrainStateTable[neighborTile];
      if ((neighbor.activeFlags1c & 3) != 0 && neighbor.gateFlag != 0) {
        CString cityName;
        g_pGlobalMapState->AssignCityRecordDisplayName(neighbor.cityRecordIndex, &cityName);
        CRgn clipRegion;
        CDC* activeDc = GetActiveQuickDrawDc();
        clipRegion.Attach(::CreateRectRgnIndirect(&tileRect));
        activeDc->SelectClipRgn(&clipRegion);
        clipRegion.DeleteObject();
        SetQuickDrawTextFont(4);
        SetQuickDrawTextSize(9);
        SetQuickDrawTextFace(0);
        int labelX = screenX - MeasureTextExtentWithCachedQuickDrawStyle(&cityName) / 2;
        if ((neighbor.activeFlags1c & 1) == 0) {
          labelX -= 10;
        }
        SetQuickDrawTextOriginWithContextOffset(static_cast<short>(labelX + 1), screenY + 10);
        SetQuickDrawFillColorFromPaletteIndex(0);
        DrawTextWithCachedQuickDrawStyleState(&cityName);
        SetQuickDrawTextOriginWithContextOffset(static_cast<short>(labelX), screenY + 9);
        SetQuickDrawFillColorFromPaletteIndex(0x13);
        DrawTextWithCachedQuickDrawStyleState(&cityName);
        SetQuickDrawFillColorFromPaletteIndex(0);
        activeDc->SelectClipRgn(0);
      }
    }

    neighborTile =
        TMapMgr::GetNeighborTileID(tileIndex, static_cast<StrategicHexDirectionStorage>(0));
    if (neighborTile != -1) {
      const TTerrainStateRecord& neighbor = g_pGlobalMapState->terrainStateTable[neighborTile];
      if ((neighbor.activeFlags1c & 3) != 0 && neighbor.gateFlag != 0) {
        CString cityName;
        g_pGlobalMapState->AssignCityRecordDisplayName(neighbor.cityRecordIndex, &cityName);
        CRgn clipRegion;
        CDC* activeDc = GetActiveQuickDrawDc();
        clipRegion.Attach(::CreateRectRgnIndirect(&tileRect));
        activeDc->SelectClipRgn(&clipRegion);
        clipRegion.DeleteObject();
        SetQuickDrawTextFont(4);
        SetQuickDrawTextSize(9);
        SetQuickDrawTextFace(0);
        int labelX = screenX + 0x40 - MeasureTextExtentWithCachedQuickDrawStyle(&cityName) / 2;
        if ((neighbor.activeFlags1c & 1) == 0) {
          labelX -= 10;
        }
        SetQuickDrawTextOriginWithContextOffset(static_cast<short>(labelX + 1), screenY + 10);
        SetQuickDrawFillColorFromPaletteIndex(0);
        DrawTextWithCachedQuickDrawStyleState(&cityName);
        SetQuickDrawTextOriginWithContextOffset(static_cast<short>(labelX), screenY + 9);
        SetQuickDrawFillColorFromPaletteIndex(0x13);
        DrawTextWithCachedQuickDrawStyleState(&cityName);
        SetQuickDrawFillColorFromPaletteIndex(0);
        activeDc->SelectClipRgn(0);
      }
    }
  }

  if (terrain.perTileVisitedFlag0f > 0) {
    int markerOffset = (terrain.perTileVisitedFlag0f - 1) << 6;
    Blit64x64StrategicMapAtlasTile(g_pMacViewMgr->atlas694[6], quickDrawSurface350, markerOffset,
                                   tileRect);
  } else if (tileIndex == g_pGlobalMapState->pendingRiverMouthTile && isOcean) {
    g_pViewMgr->SetForeColor(3);
    CRect selectionRect(screenX + 0x20, screenY + 0x20, screenX + 0x21, screenY + 0x21);
    FillRectWithQuickDrawBrushAndContextOffset(&selectionRect);
  }

  if (isOcean) {
    if (terrain.tileActionState16 >= 0 &&
        terrain.tileActionState16 < kMapTileActionStateStrategicAtlasFrameCount) {
      int actionOffset = terrain.tileActionState16 << 6;
      Blit64x64StrategicMapAtlasTile(g_pMacViewMgr->atlas690, quickDrawSurface350, actionOffset,
                                     tileRect);
    }
    return;
  }

  const int activeNation = g_pSimMgr->GetActiveNationId();
  TCivUnit* civilianOrder =
      g_pGlobalMapState->GetTileUnitEntryByOwner(tileIndex, static_cast<short>(activeNation));
  if (civilianOrder == 0) {
    civilianOrder = terrain.firstCivilianOrder20;
  }
  if (civilianOrder != 0 &&
      (terrain.ownerNationTag04 == activeNation || terrain.ownerNationTag04 > 6)) {
    RenderMapOrderEntryTilePreview(civilianOrder, screenY, screenX, 0, tileIndex);
  }

  if (tileDebugOverlayEnabled360) {
    CString tileDebugText;
    SetQuickDrawFillColor(0);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x20, screenY + 0x20);
    tileDebugText.Format(g_szDecimalFormat, static_cast<int>(terrain.cityRecordIndex));
    DrawTextWithCachedQuickDrawStyleState(&tileDebugText);
  }
}

// Two 10-way switches on the same pattern selector, each dispatching virtually into the
// guide-pattern family (slots 0x85-0x8e) with variant 1 (nationA's tint) then variant 2
// (nationB's). Ghidra's decompile of this function is broken (phantom register args from
// the deferred __cdecl stack cleanup); ported from the raw listing.
// FUNCTION: IMPERIALISM 0x00520670
void TMapDialog::DrawBorder(short relationLevel, int originX, int originY, int nationA,
                            int nationB) {
  if (g_pDiplomacyTurnStateManager->IsGreatPower(nationA) == 0) {
    g_pViewMgr->SetForeColor(0x35);
  } else {
    g_pViewMgr->SetForeColor(nationA);
  }
  SetQuickDrawPenSizeAndMarkDirty(2, 2);
  switch (relationLevel) {
  case 0:
    DrawMapDialogGuidePatternSetA_00520970(originX, originY, 1);
    break;
  case 1:
    DrawMapDialogGuidePatternSetB_00520a90(originX, originY, 1);
    break;
  case 2:
    DrawMapDialogGuidePatternSetC_00520c10(originX, originY, 1);
    break;
  case 3:
    DrawMapDialogGuidePatternSetD_00520d20(originX, originY, 1);
    break;
  case 4:
    DrawMapDialogTileGuidePatternByVariant(originX, originY, 1);
    break;
  case 5:
    DrawMapDialogGuidePatternSetE_00520fc0(originX, originY, 1);
    break;
  case 6:
    DrawMapDialogGuidePatternSetF_00521090(originX, originY, 1);
    break;
  case 7:
    DrawMapDialogGuidePatternSetG_005211c0(originX, originY, 1);
    break;
  case 8:
    DrawMapDialogGuidePatternSetH_00521340(originX, originY, 1);
    break;
  case 9:
    DrawMapDialogGuidePatternSetI_00521540(originX, originY, 1);
    break;
  }
  if (g_pDiplomacyTurnStateManager->IsGreatPower(nationB) == 0) {
    g_pViewMgr->SetForeColor(0x35);
  } else {
    g_pViewMgr->SetForeColor(nationB);
  }
  switch (relationLevel) {
  case 0:
    DrawMapDialogGuidePatternSetA_00520970(originX, originY, 2);
    break;
  case 1:
    DrawMapDialogGuidePatternSetB_00520a90(originX, originY, 2);
    break;
  case 2:
    DrawMapDialogGuidePatternSetC_00520c10(originX, originY, 2);
    break;
  case 3:
    DrawMapDialogGuidePatternSetD_00520d20(originX, originY, 2);
    break;
  case 4:
    DrawMapDialogTileGuidePatternByVariant(originX, originY, 2);
    break;
  case 5:
    DrawMapDialogGuidePatternSetE_00520fc0(originX, originY, 2);
    break;
  case 6:
    DrawMapDialogGuidePatternSetF_00521090(originX, originY, 2);
    break;
  case 7:
    DrawMapDialogGuidePatternSetG_005211c0(originX, originY, 2);
    break;
  case 8:
    DrawMapDialogGuidePatternSetH_00521340(originX, originY, 2);
    break;
  case 9:
    DrawMapDialogGuidePatternSetI_00521540(originX, originY, 2);
    break;
  }
}

// FUNCTION: IMPERIALISM 0x00520970
void TMapDialog::DrawMapDialogGuidePatternSetA_00520970(int originX, int originY, short variant) {
  int y1;
  int y2;
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x18, originY);
    DrawCenteredGuideLineOnMapDc(originX + 0x20, originY + 9);
    DrawCenteredGuideLineOnMapDc(originX + 0x26, originY + 6);
    DrawCenteredGuideLineOnMapDc(originX + 0x2c, originY + 8);
    return;
  }
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x16, originY);
    y1 = originY + 10;
    DrawCenteredGuideLineOnMapDc(originX + 0x1e, y1);
    y2 = originY + 8;
  } else {
    if (variant != 2) {
      return;
    }
    SetQuickDrawTextOriginWithContextOffset(originX + 0x1a, originY);
    y1 = originY + 6;
    DrawCenteredGuideLineOnMapDc(originX + 0x22, y1);
    y2 = originY + 4;
  }
  DrawCenteredGuideLineOnMapDc(originX + 0x26, y2);
  DrawCenteredGuideLineOnMapDc(originX + 0x2c, y1);
}

// FUNCTION: IMPERIALISM 0x00520a90
void TMapDialog::DrawMapDialogGuidePatternSetB_00520a90(int originX, int originY, short variant) {
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 8);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0xd);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x14);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x20);
    return;
  }
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 10);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0xf);
    DrawCenteredGuideLineOnMapDc(originX + 0x31, originY + 0x14);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x20);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 6);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0xb);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x13);
    DrawCenteredGuideLineOnMapDc(originX + 0x3c, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x20);
  }
}

// FUNCTION: IMPERIALISM 0x00520c10
void TMapDialog::DrawMapDialogGuidePatternSetC_00520c10(int originX, int originY, short variant) {
  int x1;
  int x2;
  int x3;
  if (variant == 1) {
    x1 = originX + 0x36;
    SetQuickDrawTextOriginWithContextOffset(x1, originY);
    x2 = originX + 0x34;
    DrawCenteredGuideLineOnMapDc(x2, originY + 9);
    x3 = originX + 0x38;
  } else if (variant == 2) {
    x1 = originX + 0x3a;
    SetQuickDrawTextOriginWithContextOffset(x1, originY);
    x2 = originX + 0x38;
    DrawCenteredGuideLineOnMapDc(x2, originY + 9);
    x3 = originX + 0x3c;
  } else {
    x1 = originX + 0x38;
    SetQuickDrawTextOriginWithContextOffset(x1, originY);
    x2 = originX + 0x36;
    DrawCenteredGuideLineOnMapDc(x2, originY + 9);
    x3 = originX + 0x3a;
  }
  DrawCenteredGuideLineOnMapDc(x3, originY + 0x12);
  DrawCenteredGuideLineOnMapDc(x2, originY + 0x19);
  DrawCenteredGuideLineOnMapDc(x1, originY + 0x20);
}

// FUNCTION: IMPERIALISM 0x00520d20
void TMapDialog::DrawMapDialogGuidePatternSetD_00520d20(int originX, int originY, short variant) {
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 10);
    DrawCenteredGuideLineOnMapDc(originX + 0x39, originY);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 5);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + -3);
    return;
  }
  SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 8);
  DrawCenteredGuideLineOnMapDc(originX + 0x38, originY);
}

// FUNCTION: IMPERIALISM 0x00520de0
void TMapDialog::DrawMapDialogTileGuidePatternByVariant(int originX, int originY, short variant) {
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 8);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0xd);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x14);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 8);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY);
    return;
  }
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 10);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0xf);
    DrawCenteredGuideLineOnMapDc(originX + 0x31, originY + 0x14);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 10);
    DrawCenteredGuideLineOnMapDc(originX + 0x39, originY);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 6);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0xb);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x13);
    DrawCenteredGuideLineOnMapDc(originX + 0x3c, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 5);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + -3);
  }
}

// FUNCTION: IMPERIALISM 0x00520fc0
void TMapDialog::DrawMapDialogGuidePatternSetE_00520fc0(int originX, int originY, short variant) {
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x36);
    DrawCenteredGuideLineOnMapDc(originX + 0x39, originY + 0x3e);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x3a);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x42);
    return;
  }
  SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x38);
  DrawCenteredGuideLineOnMapDc(originX + 0x39, originY + 0x40);
}

// FUNCTION: IMPERIALISM 0x00521090
void TMapDialog::DrawMapDialogGuidePatternSetF_00521090(int originX, int originY, short variant) {
  int x1;
  int x2;
  if (variant == 1) {
    x1 = originX + 0x36;
    SetQuickDrawTextOriginWithContextOffset(x1, originY + 0x20);
    x2 = originX + 0x34;
    DrawCenteredGuideLineOnMapDc(x2, originY + 0x29);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x32);
    DrawCenteredGuideLineOnMapDc(x2, originY + 0x39);
    DrawCenteredGuideLineOnMapDc(x1, originY + 0x40);
    return;
  } else if (variant == 2) {
    x1 = originX + 0x3a;
    SetQuickDrawTextOriginWithContextOffset(x1, originY + 0x20);
    x2 = originX + 0x38;
    DrawCenteredGuideLineOnMapDc(x2, originY + 0x29);
    DrawCenteredGuideLineOnMapDc(originX + 0x3c, originY + 0x32);
    DrawCenteredGuideLineOnMapDc(x2, originY + 0x39);
    DrawCenteredGuideLineOnMapDc(x1, originY + 0x40);
    return;
  } else {
    x1 = originX + 0x38;
    SetQuickDrawTextOriginWithContextOffset(x1, originY + 0x20);
    x2 = originX + 0x36;
    DrawCenteredGuideLineOnMapDc(x2, originY + 0x29);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x32);
    DrawCenteredGuideLineOnMapDc(x2, originY + 0x39);
    DrawCenteredGuideLineOnMapDc(x1, originY + 0x40);
  }
}

// FUNCTION: IMPERIALISM 0x005211c0
void TMapDialog::DrawMapDialogGuidePatternSetG_005211c0(int originX, int originY, short variant) {
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x38);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x33);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x2c);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x20);
    return;
  }
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x36);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x31);
    DrawCenteredGuideLineOnMapDc(originX + 0x30, originY + 0x2c);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x20);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x3a);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0x35);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x2d);
    DrawCenteredGuideLineOnMapDc(originX + 0x3c, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x20);
  }
}

// FUNCTION: IMPERIALISM 0x00521340
void TMapDialog::DrawMapDialogGuidePatternSetH_00521340(int originX, int originY, short variant) {
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x38);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x33);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x2c);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x38);
    DrawCenteredGuideLineOnMapDc(originX + 0x39, originY + 0x40);
    return;
  }
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x36);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x31);
    DrawCenteredGuideLineOnMapDc(originX + 0x30, originY + 0x2c);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x36);
    DrawCenteredGuideLineOnMapDc(originX + 0x39, originY + 0x3e);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x3a);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0x35);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x2d);
    DrawCenteredGuideLineOnMapDc(originX + 0x3c, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x3a);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x42);
  }
}

// FUNCTION: IMPERIALISM 0x00521540
void TMapDialog::DrawMapDialogGuidePatternSetI_00521540(int originX, int originY, short variant) {
  int y1;
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x18, originY + 0x40);
    DrawCenteredGuideLineOnMapDc(originX + 0x1a, originY + 0x3b);
    DrawCenteredGuideLineOnMapDc(originX + 0x24, originY + 0x36);
    y1 = originY + 0x38;
  } else if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x16, originY + 0x3f);
    DrawCenteredGuideLineOnMapDc(originX + 0x18, originY + 0x39);
    DrawCenteredGuideLineOnMapDc(originX + 0x24, originY + 0x33);
    y1 = originY + 0x36;
  } else {
    if (variant != 2) {
      return;
    }
    SetQuickDrawTextOriginWithContextOffset(originX + 0x1a, originY + 0x40);
    DrawCenteredGuideLineOnMapDc(originX + 0x1c, originY + 0x3b);
    DrawCenteredGuideLineOnMapDc(originX + 0x24, originY + 0x38);
    y1 = originY + 0x3a;
  }
  DrawCenteredGuideLineOnMapDc(originX + 0x2a, y1);
  DrawCenteredGuideLineOnMapDc(originX + 0x2c, y1);
}

// Draws the city-region boundary pieces selected by the six-direction border mask. The
// compound 0x40/0x80 bits add the short joins between adjacent directional segments.
// FUNCTION: IMPERIALISM 0x00521680
void TMapDialog::DrawCityBorderSegmentsByMask(unsigned char borderMask, int screenX, int screenY,
                                              short tileIndex) {
  const bool direction1 = (borderMask & 2) != 0;
  if (direction1) {
    SetQuickDrawPenSizeAndMarkDirty(1, 1);
    SetQuickDrawFillColor(0xffffff);
    if ((borderMask & 1) == 0) {
      DrawMapDialogGuidePatternSetC_00520c10(screenX, screenY, 0);
    } else {
      DrawMapDialogGuidePatternSetB_00520a90(screenX, screenY, 0);
      if ((borderMask & 0x40) != 0) {
        SetQuickDrawPenSizeAndMarkDirty(1, 1);
        SetQuickDrawFillColor(0xffffff);
        DrawMapDialogGuidePatternSetD_00520d20(screenX, screenY, 0);
      }
    }

    SetQuickDrawPenSizeAndMarkDirty(1, 1);
    SetQuickDrawFillColor(0xffffff);
    if ((borderMask & 4) == 0) {
      DrawMapDialogGuidePatternSetF_00521090(screenX, screenY, 0);
    } else {
      DrawMapDialogGuidePatternSetG_005211c0(screenX, screenY, 0);
      if ((borderMask & 0x80) != 0) {
        SetQuickDrawPenSizeAndMarkDirty(1, 1);
        SetQuickDrawFillColor(0xffffff);
        DrawMapDialogGuidePatternSetE_00520fc0(screenX, screenY, 0);
      }
    }
  }

  if ((borderMask & 1) != 0) {
    SetQuickDrawPenSizeAndMarkDirty(1, 1);
    SetQuickDrawFillColor(0xffffff);
    DrawMapDialogGuidePatternSetA_00520970(screenX, screenY, 0);
    if (!direction1) {
      SetQuickDrawPenSizeAndMarkDirty(1, 1);
      SetQuickDrawFillColor(0xffffff);
      DrawMapDialogGuidePatternSetD_00520d20(screenX, screenY, 0);
    }
  }
  if ((borderMask & 4) != 0) {
    SetQuickDrawPenSizeAndMarkDirty(1, 1);
    SetQuickDrawFillColor(0xffffff);
    DrawMapDialogGuidePatternSetI_00521540(screenX, screenY, 0);
    if (!direction1) {
      SetQuickDrawPenSizeAndMarkDirty(1, 1);
      SetQuickDrawFillColor(0xffffff);
      DrawMapDialogGuidePatternSetE_00520fc0(screenX, screenY, 0);
    }
  }

  if (g_pGlobalMapState->terrainStateTable[tileIndex].GetTerrainKind() != kStrategicTerrainWater) {
    short neighborTile =
        g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionNorthEast);
    if (neighborTile != -1 &&
        g_pGlobalMapState->terrainStateTable[neighborTile].GetTerrainKind() ==
            kStrategicTerrainWater &&
        (borderMask & 0x20) != 0 && !direction1) {
      SetQuickDrawPenSizeAndMarkDirty(1, 1);
      SetQuickDrawFillColor(0xffffff);
      DrawMapDialogGuidePatternSetA_00520970(screenX, screenY, 0);
      DrawMapDialogGuidePatternSetD_00520d20(screenX, screenY, 0);
    }

    neighborTile = g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionSouthEast);
    if (neighborTile != -1 &&
        g_pGlobalMapState->terrainStateTable[neighborTile].GetTerrainKind() ==
            kStrategicTerrainWater &&
        (borderMask & 8) != 0 && !direction1) {
      SetQuickDrawPenSizeAndMarkDirty(1, 1);
      SetQuickDrawFillColor(0xffffff);
      DrawMapDialogGuidePatternSetE_00520fc0(screenX, screenY, 0);
      DrawMapDialogGuidePatternSetI_00521540(screenX, screenY, 0);
    }
    SetQuickDrawPenSizeAndMarkDirty(1, 1);
  }
}

// Draws the same directional border geometry with each segment split into the two nations'
// colors. Neighbor directions and guide-pattern indices follow the retail 0x521a40 dispatch.
// FUNCTION: IMPERIALISM 0x00521a40
void TMapDialog::DrawNationBorderSegmentsByMask(unsigned char borderMask, int screenX, int screenY,
                                                short tileIndex) {
  const unsigned char direction1 = borderMask & 2;
  short neighborTile;

  if (direction1) {
    neighborTile = g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionEast);
    short neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
    if ((borderMask & 1) == 0) {
      DrawBorder(2, screenX, screenY,
                 g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
    } else {
      DrawBorder(1, screenX, screenY,
                 g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
      if ((borderMask & 0x40) != 0) {
        neighborTile =
            g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionNorthEast);
        neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
        DrawBorder(3, screenX, screenY,
                   g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04,
                   neighborNation);
      }
    }

    if ((borderMask & 4) == 0) {
      neighborTile = g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionEast);
      neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
      DrawBorder(6, screenX, screenY,
                 g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
    } else {
      neighborTile =
          g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionSouthEast);
      neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
      DrawBorder(7, screenX, screenY,
                 g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
      if ((borderMask & 0x80) != 0) {
        neighborTile =
            g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionSouthEast);
        neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
        DrawBorder(5, screenX, screenY,
                   g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04,
                   neighborNation);
      }
    }
  }

  if ((borderMask & 1) != 0) {
    neighborTile = g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionNorthEast);
    short neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
    DrawBorder(0, screenX, screenY,
               g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
    if (!direction1) {
      neighborTile =
          g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionNorthEast);
      neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
      DrawBorder(3, screenX, screenY,
                 g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
    }
  }
  if ((borderMask & 4) != 0) {
    neighborTile = g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionSouthEast);
    short neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
    DrawBorder(9, screenX, screenY,
               g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
    if (!direction1) {
      neighborTile =
          g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionSouthEast);
      neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
      DrawBorder(5, screenX, screenY,
                 g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
    }
  }

  if (g_pGlobalMapState->terrainStateTable[tileIndex].GetTerrainKind() != kStrategicTerrainWater) {
    neighborTile = g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionNorthEast);
    if (neighborTile != -1 &&
        g_pGlobalMapState->terrainStateTable[neighborTile].GetTerrainKind() ==
            kStrategicTerrainWater &&
        (borderMask & 0x20) != 0 && !direction1) {
      neighborTile =
          g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionNorthWest);
      short neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
      DrawBorder(0, screenX, screenY,
                 g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
      neighborTile =
          g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionNorthWest);
      neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
      DrawBorder(3, screenX, screenY,
                 g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
    }

    neighborTile = g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionSouthEast);
    if (neighborTile != -1 &&
        g_pGlobalMapState->terrainStateTable[neighborTile].GetTerrainKind() ==
            kStrategicTerrainWater &&
        (borderMask & 8) != 0 && !direction1) {
      neighborTile =
          g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionSouthWest);
      short neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
      DrawBorder(5, screenX, screenY,
                 g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
      neighborTile =
          g_pGlobalMapState->GetNeighborTileID(tileIndex, kStrategicHexDirectionSouthWest);
      neighborNation = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
      DrawBorder(9, screenX, screenY,
                 g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04, neighborNation);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00522000
void TMapDialog::DrawSeaZoneBorders(unsigned char edgeMask, int screenX, int screenY,
                                    short tileIndex) {
  g_pViewMgr->SetForeColor(g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04);
  if ((edgeMask & 0x20) != 0) {
    SetQuickDrawTextOriginWithContextOffset(screenX + 8, screenY + 8);
    DrawCenteredGuideLineOnMapDc(screenX + 0xc, screenY + 8);
    return;
  }
  if ((edgeMask & 8) != 0) {
    SetQuickDrawTextOriginWithContextOffset(screenX + 8, screenY + 0x38);
    DrawCenteredGuideLineOnMapDc(screenX + 0xc, screenY + 0x38);
    return;
  }
  if ((edgeMask & 2) != 0) {
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x2c, screenY + 0x2e);
    DrawCenteredGuideLineOnMapDc(screenX + 0x30, screenY + 0x2e);
  }
}

// FUNCTION: IMPERIALISM 0x005220f0
void TMapDialog::DrawSeaZoneBorders(int screenX, int screenY, short tileIndex) {
  short neighbors[6];
  TMapMgr::GetNeighborTileIDArray(tileIndex, neighbors,
                                  g_pGlobalMapState->hexNeighborWrapHorizontally);

  if (LandTilesHaveDifferentNationOwners(neighbors[3], neighbors[2])) {
    SetMapBorderColorForTileOwner(neighbors[3]);
    SetQuickDrawPenSizeAndMarkDirty(2, 2);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x16, screenY + 0x40);
    DrawCenteredGuideLineOnMapDc(screenX + 0x16, screenY + 0x38);

    SetMapBorderColorForTileOwner(neighbors[2]);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x1a, screenY + 0x40);
    DrawCenteredGuideLineOnMapDc(screenX + 0x1a, screenY + 0x38);

    SetQuickDrawFillColor(0xffffff);
    SetQuickDrawPenSizeAndMarkDirty(1, 1);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x18, screenY + 0x40);
    DrawCenteredGuideLineOnMapDc(screenX + 0x18, screenY + 0x38);
  }

  if (LandTilesHaveDifferentNationOwners(neighbors[2], neighbors[1])) {
    SetMapBorderColorForTileOwner(neighbors[2]);
    SetQuickDrawPenSizeAndMarkDirty(2, 2);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x36, screenY + 0x40);
    DrawCenteredGuideLineOnMapDc(screenX + 0x36, screenY + 0x36);
    DrawCenteredGuideLineOnMapDc(screenX + 0x31, screenY + 0x2e);

    SetMapBorderColorForTileOwner(neighbors[1]);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x39, screenY + 0x40);
    DrawCenteredGuideLineOnMapDc(screenX + 0x39, screenY + 0x36);
    DrawCenteredGuideLineOnMapDc(screenX + 0x34, screenY + 0x2a);

    SetQuickDrawFillColor(0xffffff);
    SetQuickDrawPenSizeAndMarkDirty(1, 1);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY + 0x40);
    DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x36);
    DrawCenteredGuideLineOnMapDc(screenX + 0x33, screenY + 0x2c);
  }

  if (LandTilesHaveDifferentNationOwners(neighbors[4], neighbors[3])) {
    SetMapBorderColorForTileOwner(neighbors[4]);
    SetQuickDrawPenSizeAndMarkDirty(2, 2);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x16, screenY + 0x40);
    DrawCenteredGuideLineOnMapDc(screenX + 0x16, screenY + 0x38);

    SetMapBorderColorForTileOwner(neighbors[3]);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x19, screenY + 0x40);
    DrawCenteredGuideLineOnMapDc(screenX + 0x19, screenY + 0x38);

    SetQuickDrawFillColor(0xffffff);
    SetQuickDrawPenSizeAndMarkDirty(1, 1);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x18, screenY + 0x40);
    DrawCenteredGuideLineOnMapDc(screenX + 0x18, screenY + 0x38);
  }

  if (LandTilesHaveDifferentNationOwners(neighbors[5], neighbors[0])) {
    SetMapBorderColorForTileOwner(neighbors[5]);
    SetQuickDrawPenSizeAndMarkDirty(2, 2);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x16, screenY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x16, screenY + 8);

    SetMapBorderColorForTileOwner(neighbors[0]);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x1a, screenY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x1a, screenY + 8);

    SetQuickDrawFillColor(0xffffff);
    SetQuickDrawPenSizeAndMarkDirty(1, 1);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x18, screenY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x18, screenY + 8);
  }

  if (LandTilesHaveDifferentNationOwners(neighbors[0], neighbors[1])) {
    SetMapBorderColorForTileOwner(neighbors[0]);
    SetQuickDrawPenSizeAndMarkDirty(2, 2);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x36, screenY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x36, screenY + 8);

    SetMapBorderColorForTileOwner(neighbors[1]);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x3a, screenY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x3a, screenY + 8);

    SetQuickDrawFillColor(0xffffff);
    SetQuickDrawPenSizeAndMarkDirty(1, 1);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 8);
  }

  if (LandTilesHaveDifferentNationOwners(neighbors[4], neighbors[5])) {
    SetMapBorderColorForTileOwner(neighbors[4]);
    SetQuickDrawPenSizeAndMarkDirty(2, 2);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x16, screenY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x16, screenY + 8);

    SetMapBorderColorForTileOwner(neighbors[5]);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x1a, screenY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x1a, screenY + 8);

    SetQuickDrawFillColor(0xffffff);
    SetQuickDrawPenSizeAndMarkDirty(1, 1);
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x18, screenY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x18, screenY + 8);
  }
  SetQuickDrawFillColor(0);
}

// Draws a guide line between two tiles' screen centers, wrapping the far tile across the
// 108-column seam and culling the line when both endpoints fall off the same screen edge.
// FUNCTION: IMPERIALISM 0x00522c10
void TMapDialog::DrawWrappedMapRouteSegment(short col1, int row1, short col2, int row2) {
  if (abs(static_cast<int>(col1) - static_cast<int>(col2)) > 0x6c) {
    if (col1 > 0x6c) {
      col1 = col1 - 0xd8;
    } else if (col2 > 0x6c) {
      col2 = col2 - 0xd8;
    }
  }
  if (col1 < 0) {
    if (col2 < 0) {
      return;
    }
  } else if (col1 > 0x12 && col2 > 0x12) {
    return;
  }
  if (static_cast<short>(row1) < 0) {
    if (static_cast<short>(row2) < 0) {
      return;
    }
  } else if (static_cast<short>(row1) > 8 && static_cast<short>(row2) > 8) {
    return;
  }

  const int firstX = (col1 * 0x40) / 2 + 0x40;
  const int firstY = (row1 + 1) * 0x40;
  const int secondX = (col2 * 0x40) / 2 + 0x40;
  const int secondY = (row2 + 1) * 0x40;
  const int dx = secondX - firstX;
  const int dy = secondY - firstY;
  int span = abs(dx);
  if (span < abs(dy)) {
    span = abs(dy);
  }
  int steps = span / 4;
  if (steps < 1) {
    steps = 1;
  }

  bool drawingWater = false;
  for (int step = 0; step <= steps; ++step) {
    int x = firstX + dx * step / steps;
    int y = firstY + dy * step / steps;
    CPoint mapPoint(x - 0x40, y - 0x40);
    short column;
    short row;
    short band;
    ConvertPoint(mapPoint, column, row, band);
    int tileIndex = static_cast<int>(row) * 0x6c + column;
    bool isWater =
        tileIndex >= 0 && tileIndex < 0x1950 &&
        g_pGlobalMapState->terrainStateTable[tileIndex].GetTerrainKind() == kStrategicTerrainWater;
    if (!isWater) {
      drawingWater = false;
    } else if (!drawingWater) {
      SetQuickDrawTextOriginWithContextOffset(x, y);
      drawingWater = true;
    } else {
      DrawCenteredGuideLineOnMapDc(x, y);
    }
  }
}

// Draws the coastline "connection" line pattern linking this ocean tile to its ocean
// neighbors, per the 6-bit connectionMask (which adjacent hexes are ocean and joined).
// FUNCTION: IMPERIALISM 0x00522cf0
void TMapDialog::DrawHexNeighborConnectionMask(unsigned char connectionMask, int screenX,
                                               int screenY, short tileIndex) {
  short neighborTiles[6];
  TMapMgr::GetNeighborTileIDArray(tileIndex, neighborTiles,
                                  g_pGlobalMapState->hexNeighborWrapHorizontally);
  TTerrainStateRecord* tiles = g_pGlobalMapState->terrainStateTable;
  unsigned char northeastOcean = connectionMask & 2;

  if ((connectionMask & 2) != 0 &&
      tiles[neighborTiles[1]].GetTerrainKind() == kStrategicTerrainWater) {
    if ((connectionMask & 1) == 0 ||
        tiles[neighborTiles[2]].GetTerrainKind() != kStrategicTerrainWater) {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY);
      DrawCenteredGuideLineOnMapDc(screenX + 0x30, screenY + 8);
      DrawCenteredGuideLineOnMapDc(screenX + 0x30, screenY + 0x14);
      DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x20);
    } else {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x2c, screenY + 8);
      DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x14);
      DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x20);
      if ((connectionMask & 0x40) != 0) {
        SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY + 0x14);
        DrawCenteredGuideLineOnMapDc(screenX + 0x3c, screenY + 8);
        DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY);
      }
    }

    int bottomY;
    if ((connectionMask & 4) == 0 ||
        tiles[neighborTiles[0]].GetTerrainKind() != kStrategicTerrainWater) {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY + 0x20);
      DrawCenteredGuideLineOnMapDc(screenX + 0x3c, screenY + 0x28);
      bottomY = screenY + 0x34;
    } else {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY + 0x20);
      DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x28);
      DrawCenteredGuideLineOnMapDc(screenX + 0x2c, screenY + 0x38);
      if ((connectionMask & 0x80) == 0) {
        goto tail;
      }
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY + 0x28);
      bottomY = screenY + 0x38;
    }
    DrawCenteredGuideLineOnMapDc(screenX + 0x3c, bottomY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x40);
  }

tail:
  if ((connectionMask & 1) != 0 &&
      tiles[neighborTiles[2]].GetTerrainKind() == kStrategicTerrainWater) {
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x18, screenY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x20, screenY + 8);
    DrawCenteredGuideLineOnMapDc(screenX + 0x2c, screenY + 8);
    if (northeastOcean == 0 && tiles[neighborTiles[1]].GetTerrainKind() == kStrategicTerrainWater) {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY);
      DrawCenteredGuideLineOnMapDc(screenX + 0x30, screenY + 8);
      DrawCenteredGuideLineOnMapDc(screenX + 0x2c, screenY + 8);
    }
  }
  if ((connectionMask & 4) != 0 &&
      tiles[neighborTiles[0]].GetTerrainKind() == kStrategicTerrainWater) {
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x18, screenY + 0x40);
    DrawCenteredGuideLineOnMapDc(screenX + 0x20, screenY + 0x38);
    DrawCenteredGuideLineOnMapDc(screenX + 0x2c, screenY + 0x38);
    if (northeastOcean == 0 && tiles[neighborTiles[1]].GetTerrainKind() == kStrategicTerrainWater) {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x2c, screenY + 0x38);
      DrawCenteredGuideLineOnMapDc(screenX + 0x30, screenY + 0x38);
      DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x40);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00523060
void TMapDialog::DrawGeneratedMapRouteSegmentsAndResetFillColor() {
  g_pViewMgr->SetForeColor(0x3c);

  int viewportRowPixels = viewportOrigin.y;
  if (viewportRowPixels < 0) {
    viewportRowPixels += 0x3f;
  }
  short viewportRow = viewportRowPixels >> 6;

  int viewportColumnPixels = viewportOrigin.x;
  if (viewportColumnPixels < 0) {
    viewportColumnPixels += 0x1f;
  }
  short viewportHalfColumn = viewportColumnPixels >> 5;

  for (int i = 0; i < g_pActiveMapOrderContext->routeNodeCount; ++i) {
    const CRect& segment = g_pActiveMapOrderContext->routeSegments[i];
    short firstColumn = (segment.left - viewportHalfColumn + 0xd8) % 0xd8;
    // CRect stores Win32 long coordinates; DrawWrappedMapRouteSegment intentionally consumes
    // the low word of each vertical endpoint.
    short firstRow = static_cast<short>(segment.top);
    firstRow -= viewportRow;
    short secondColumn = (segment.right - viewportHalfColumn + 0xd8) % 0xd8;
    short secondRow = static_cast<short>(segment.bottom);
    secondRow -= viewportRow;
    DrawWrappedMapRouteSegment(firstColumn, firstRow, secondColumn, secondRow);
  }

  SetQuickDrawFillColor(0);
}

// FUNCTION: IMPERIALISM 0x00523170
void TMapDialog::DrawTile(short tileIndex, short screenX, short screenY) {
  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags = 0;
  GetGWorld(&savedSurface, &savedSurfaceFlags);
  ResetQuickDrawStrokeState();
  SetGWorld(quickDrawSurface350, savedSurfaceFlags);
  LockPixels(GetGWorldPixMap(g_pCitySiteCachedPrimaryRenderSurfaceContext));
  LockPixels(GetGWorldPixMap(quickDrawSurface350));

  int markerIndex = 0;
  while (markerIndex < 90 && tileMarkers7c[markerIndex].c != tileIndex) {
    ++markerIndex;
  }
  if (markerIndex == 90) {
    markerIndex = 0;
    while (markerIndex < 90 && tileMarkers7c[markerIndex].flag != 0) {
      ++markerIndex;
    }
  }
  if (markerIndex == 90) {
    SetGWorld(savedSurface, savedSurfaceFlags);
    return;
  }

  TMapDialogTileMarker& marker = tileMarkers7c[markerIndex];
  if (marker.c >= 0 && marker.c != tileIndex) {
    g_pGlobalMapState->terrainStateTable[marker.c].markerSlotIndex10 = -1;
  }
  marker.flag = 1;
  SplitTileIndexToRowAndColumn(tileIndex, &marker.a, &marker.b);
  marker.c = tileIndex;
  g_pGlobalMapState->terrainStateTable[tileIndex].markerSlotIndex10 =
      static_cast<signed char>(markerIndex);
  DrawOneTile(tileIndex, 0, markerIndex << 6);

  RECT sourceRect = {markerIndex << 6, 0, (markerIndex + 1) << 6, 0x40};
  RECT cacheRect = {screenX + 0x40, screenY + 0x40, screenX + 0x80, screenY + 0x80};
  BlitRectWithOptionalTransparency(quickDrawSurface350->GetBlitSurface(),
                                   g_pCitySiteCachedPrimaryRenderSurfaceContext->GetBlitSurface(),
                                   &sourceRect, &cacheRect, 0, 0);

  TCivUnit* firstCivilianOrder =
      g_pGlobalMapState->terrainStateTable[tileIndex].firstCivilianOrder20;
  if (firstCivilianOrder != 0) {
    TAnimation* animation =
        g_pUiAnimator->FindRegisteredAnimationByTag(PointerAddressLong32(firstCivilianOrder));
    if (animation != 0) {
      SetGWorld(g_pCitySiteCachedPrimaryRenderSurfaceContext, savedSurfaceFlags);
      RECT animationClip = animation->screenRect;
      OffsetRect(&animationClip, 0x40, 0x40);
      ClipRect(&animationClip);
      POINT drawOffset = {0x40, 0x40};
      animation->DrawNextFrame(&drawOffset);
      SetGWorld(quickDrawSurface350, savedSurfaceFlags);
    }
  }

  ResetQuickDrawStrokeState();
  SetGWorld(savedSurface, savedSurfaceFlags);
  RECT destinationRect = {screenX, screenY, screenX + 0x40, screenY + 0x40};
  BlitRectWithOptionalTransparency(g_pCitySiteCachedPrimaryRenderSurfaceContext->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &cacheRect,
                                   &destinationRect, 0, 0);
  UnlockPixels(GetGWorldPixMap(g_pCitySiteCachedPrimaryRenderSurfaceContext));
  UnlockPixels(GetGWorldPixMap(quickDrawSurface350));
}

// FUNCTION: IMPERIALISM 0x00523640
void TMapDialog::RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int projectedX,
                                                int projectedY, int flag, short tileIndex) {
  bool belongsToActiveNation = orderEntry->ownerNationSlot18 == g_pSimMgr->GetActiveNationId();
  if (orderEntry->unitOrder > static_cast<UnitOrder>(4) && belongsToActiveNation) {
    int animationTag = PointerAddressLong32(orderEntry);
    if (g_pUiAnimator->FindRegisteredAnimationByTag(animationTag) == 0) {
      short animationY;
      short animationX;
      ProjectTileIndexToWrappedScreenOffsetByScale(tileIndex, &viewportOrigin, &animationY,
                                                   &animationX, 1);
      CRect animationRect(animationX, animationY, animationX + 0x40, animationY + 0x40);
      TCivAnimation2* animation =
          new TCivAnimation2(this, &animationRect, orderEntry->orderType, animationTag);
      g_pUiAnimator->AddObjectToUiTransientRegistry(animation);
    }
    return;
  }

  TQuickDrawSurfaceContext* destinationSurface =
      flag == 0 ? quickDrawSurface350 : g_pActiveQuickDrawSurfaceContext;
  CRect destinationRect(projectedY, projectedX, projectedY + 0x40, projectedX + 0x40);

  if (flag != 0 && alternateOverlayEnabled == 0) {
    signed char markerIndex =
        g_pGlobalMapState->terrainStateTable[orderEntry->tileIndex06].markerSlotIndex10;
    if (markerIndex != -1) {
      CRect sourceRect(markerIndex << 6, 0, (markerIndex + 1) << 6, 0x40);
      BlitRectWithOptionalTransparency(quickDrawSurface350->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &sourceRect, &destinationRect, 0, 0);
    }
    if (cursorId4e != 0xffff && cursorId4e != 0x3f0) {
      CPoint currentMousePoint;
      CopyCurrentMouseCapturePoint(&currentMousePoint);
      if (destinationRect.PtInRect(currentMousePoint)) {
        QDFrameRect(&destinationRect);
      }
    }
    return;
  }

  short spriteOffset = g_pGlobalMapState->ApplyMapImprovementSelectionState(orderEntry);
  if (flag != 0) {
    spriteOffset = static_cast<short>(spriteOffset + 0x240);
  }
  CRect spriteSourceRect(spriteOffset, 0, spriteOffset + 0x40, 0x40);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas66c->GetBlitSurface(),
                                   destinationSurface->GetBlitSurface(), &spriteSourceRect,
                                   &destinationRect, 0x24, 0);

  if (flag == 0 && !belongsToActiveNation) {
    short ownerBadgeX =
        g_pGlobalMapState->GetMapImprovementTierBucketOffset(orderEntry->ownerNationSlot18);
    CRect ownerSourceRect(ownerBadgeX, 0, ownerBadgeX + 9, 6);
    CRect ownerDestinationRect(destinationRect.left + 0x1c, destinationRect.bottom - 8,
                               destinationRect.left + 0x25, destinationRect.bottom - 2);
    if (destinationSurface->blitSurface.surfaceDib != 0) {
      int surfaceHeight = destinationSurface->blitSurface.surfaceDib->GetAbsoluteHeight();
      OffsetRect(&ownerDestinationRect, 0,
                 (surfaceHeight - ownerDestinationRect.top) - ownerDestinationRect.bottom);
    }
    BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas6b8->GetBlitSurface(),
                                     destinationSurface->GetBlitSurface(), &ownerSourceRect,
                                     &ownerDestinationRect, 0x24, 0);
    destinationRect.InflateRect(1, 1);
    SetQuickDrawFillColorFromPaletteIndex(0x13);
    QDFrameRect(&destinationRect);
  }
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x00523b70
void TMapDialog::RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, CRect* dstRect,
                                                               int flag) {
  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  short cityRecordIndex = tile.cityRecordIndex;
  TMilitaryUnit* unit = 0;
  if (cityRecordIndex >= 0 && cityRecordIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[cityRecordIndex].stationedUnitChain98;
  }
  if (unit == 0) {
    return;
  }

  if (flag != 0 && alternateOverlayEnabled == 0) {
    signed char markerIndex = tile.markerSlotIndex10;
    if (markerIndex == -1) {
      return;
    }
    CRect sourceRect(markerIndex << 6, 0, (markerIndex + 1) << 6, 0x40);
    BlitRectWithOptionalTransparency(quickDrawSurface350->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect, dstRect, 0, 0);
    return;
  }

  short displayedUnitCount = 0;
  for (TMilitaryUnit* current = unit; current != 0;
       current = static_cast<TMilitaryUnit*>(current->nextAtLocation14)) {
    if (current->orderType != EncodeMilitaryUnitKind(kMilitaryUnitMinutemen) &&
        current->orderType != EncodeMilitaryUnitKind(kMilitaryUnitMilitia) &&
        current->orderType != EncodeMilitaryUnitKind(kMilitaryUnitConscripts)) {
      ++displayedUnitCount;
    }
  }
  int countBucket = 0;
  if (displayedUnitCount != 0) {
    if (displayedUnitCount < 6) {
      countBucket = 1;
    } else {
      countBucket = displayedUnitCount >= 0xb ? 3 : 2;
    }
  }

  TQuickDrawSurfaceContext* destinationSurface =
      flag == 0 ? quickDrawSurface350 : g_pActiveQuickDrawSurfaceContext;
  short countSpriteX =
      static_cast<short>(g_pGlobalMapState->ComputeTerrainRecordByteOffsetForIndex(countBucket));
  if (flag != 0) {
    countSpriteX = static_cast<short>(countSpriteX + 0x12);
  }
  CRect countSourceRect(countSpriteX, 0, countSpriteX + 0x12, 0x26);
  CRect countDestinationRect;
  if (destinationSurface->blitSurface.surfaceDib != 0) {
    countDestinationRect.SetRect(dstRect->left, dstRect->bottom - 0x26, dstRect->left + 0x12,
                                 dstRect->bottom);
  } else {
    countDestinationRect.SetRect(dstRect->left, dstRect->top, dstRect->left + 0x12,
                                 dstRect->top + 0x26);
  }

  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas6b4->GetBlitSurface(),
                                   destinationSurface->GetBlitSurface(), &countSourceRect,
                                   &countDestinationRect, 0x24, 0);

  short ownerBadgeX = g_pGlobalMapState->GetMapImprovementTierBucketOffset(tile.ownerNationTag04);
  CRect ownerSourceRect(ownerBadgeX, 0, ownerBadgeX + 9, 6);
  CRect ownerDestinationRect;
  if (destinationSurface->blitSurface.surfaceDib != 0) {
    ownerDestinationRect.SetRect(dstRect->left + 7, dstRect->bottom - 8, dstRect->left + 0x10,
                                 dstRect->bottom - 2);
  } else {
    ownerDestinationRect.SetRect(dstRect->left + 7, dstRect->top + 2, dstRect->left + 0x10,
                                 dstRect->top + 8);
  }
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas6b8->GetBlitSurface(),
                                   destinationSurface->GetBlitSurface(), &ownerSourceRect,
                                   &ownerDestinationRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x00523ff0
void TMapDialog::RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, CRect* dstRect,
                                                               unsigned char altOverlay) {
  MapTileActionStateStorage tileActionClass =
      g_pGlobalMapState->terrainStateTable[tileIndex].tileActionState16;
  if (tileActionClass < 0 || tileActionClass >= kMapTileActionStateOceanAtlasFrameCount) {
    return;
  }

  if (altOverlay == 0) {
    CRect sourceRect(tileActionClass << 6, 0, (tileActionClass + 1) << 6, 0x40);
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas690->GetBlitSurface(),
                                     quickDrawSurface350->GetBlitSurface(), &sourceRect, dstRect,
                                     0x24, 0);
    UpdatePaletteIndexWithDefaultFallback(0x13);
    return;
  }

  if (alternateOverlayEnabled == 0) {
    signed char terrainFrameIndex =
        g_pGlobalMapState->terrainStateTable[tileIndex].markerSlotIndex10;
    if (terrainFrameIndex == -1) {
      return;
    }
    CRect sourceRect(terrainFrameIndex << 6, 0, (terrainFrameIndex + 1) << 6, 0x40);
    BlitRectWithOptionalTransparency(quickDrawSurface350->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect, dstRect, 0, 0);
    return;
  }

  int sourceX = (tileActionClass + 1) << 6;
  CRect sourceRect(sourceX, 0, sourceX + 0x40, 0x40);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas690->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &sourceRect,
                                   dstRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

static inline void CopyMapTilePixelSpan(unsigned char* src, unsigned char* dest, short srcStride,
                                        short destStride, int row, int firstColumn,
                                        int pixelCount) {
  src += row * srcStride + firstColumn;
  dest += row * destStride + firstColumn;
  while (pixelCount > 0) {
    *dest++ = *src++;
    --pixelCount;
  }
}

// The twelve masks below are the exact per-row byte spans written by the retail routines.
// Their original dword-copy loops were decoded by executing the isolated routines against a
// synthetic 64x64 destination and recording every destination byte write.
// FUNCTION: IMPERIALISM 0x005241b0
void TMapDialog::CopyTerrainTransitionMaskDirection2(unsigned char* src, unsigned char* dest,
                                                     short srcStride, short destStride) {
  for (int rowDirection2 = 0; rowDirection2 < 0x20; ++rowDirection2) {
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, rowDirection2, 0x20,
                         0x20 - rowDirection2);
  }
}

// FUNCTION: IMPERIALISM 0x005242f0
void TMapDialog::CopyTerrainTransitionMaskDirection1(unsigned char* src, unsigned char* dest,
                                                     short srcStride, short destStride) {
  for (int upperRowDirection1 = 1; upperRowDirection1 < 0x20; ++upperRowDirection1) {
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, upperRowDirection1,
                         0x40 - upperRowDirection1, upperRowDirection1);
  }
  for (int lowerRowDirection1 = 0x20; lowerRowDirection1 < 0x3f; ++lowerRowDirection1) {
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, lowerRowDirection1,
                         lowerRowDirection1 + 1, 0x3f - lowerRowDirection1);
  }
}

// FUNCTION: IMPERIALISM 0x00524540
void TMapDialog::CopyTerrainTransitionMaskDirection0(unsigned char* src, unsigned char* dest,
                                                     short srcStride, short destStride) {
  for (int rowDirection0 = 0x20; rowDirection0 < 0x40; ++rowDirection0) {
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, rowDirection0, 0x20,
                         rowDirection0 - 0x1f);
  }
}

// FUNCTION: IMPERIALISM 0x00524670
void TMapDialog::CopyTerrainTransitionMaskDirection5(unsigned char* src, unsigned char* dest,
                                                     short srcStride, short destStride) {
  for (int rowDirection5 = 0x21; rowDirection5 < 0x40; ++rowDirection5) {
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, rowDirection5, 0x40 - rowDirection5,
                         rowDirection5 - 0x20);
  }
}

// FUNCTION: IMPERIALISM 0x005247a0
void TMapDialog::CopyTerrainTransitionMaskDirection4(unsigned char* src, unsigned char* dest,
                                                     short srcStride, short destStride) {
  for (int upperRowDirection4 = 0; upperRowDirection4 < 0x20; ++upperRowDirection4) {
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, upperRowDirection4, 0,
                         upperRowDirection4 + 1);
  }
  for (int lowerRowDirection4 = 0x20; lowerRowDirection4 < 0x40; ++lowerRowDirection4) {
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, lowerRowDirection4, 0,
                         0x40 - lowerRowDirection4);
  }
}

// FUNCTION: IMPERIALISM 0x005249f0
void TMapDialog::CopyTerrainTransitionMaskDirection3(unsigned char* src, unsigned char* dest,
                                                     short srcStride, short destStride) {
  for (int rowDirection3 = 0; rowDirection3 < 0x20; ++rowDirection3) {
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, rowDirection3, rowDirection3,
                         0x20 - rowDirection3);
  }
}

// FUNCTION: IMPERIALISM 0x00524b30
void TMapDialog::CopyCoastCornerMaskBetweenDirections1And2(unsigned char* src, unsigned char* dest,
                                                           short srcStride, short destStride) {
  for (int rowDirections1And2 = 0; rowDirections1And2 < 0x20; ++rowDirections1And2) {
    int firstColumn = 0x30 - (rowDirections1And2 / 8) * 4;
    if ((rowDirections1And2 & 2) != 0) {
      --firstColumn;
    }
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, rowDirections1And2, firstColumn,
                         0x40 - firstColumn);
  }
}

// FUNCTION: IMPERIALISM 0x00524c60
void TMapDialog::CopyCoastCornerMaskBetweenDirections0And1(unsigned char* src, unsigned char* dest,
                                                           short srcStride, short destStride) {
  for (int rowDirections0And1 = 0x20; rowDirections0And1 < 0x40; ++rowDirections0And1) {
    int firstColumn = 0x20 + (rowDirections0And1 - 0x20) / 2;
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, rowDirections0And1, firstColumn,
                         0x40 - firstColumn);
  }
}

// FUNCTION: IMPERIALISM 0x00524e70
void TMapDialog::CopyCoastCornerMaskBetweenDirections2And3(unsigned char* src, unsigned char* dest,
                                                           short srcStride, short destStride) {
  for (int rowDirections2And3 = 0; rowDirections2And3 < 0x20; ++rowDirections2And3) {
    int firstColumn = 0x10 + rowDirections2And3 / 2;
    int pairInGroup = (rowDirections2And3 / 2) & 3;
    int endColumn = 0x30 + ((4 - pairInGroup) & 3);
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, rowDirections2And3, firstColumn,
                         endColumn - firstColumn);
  }
}

// FUNCTION: IMPERIALISM 0x005250a0
void TMapDialog::CopyCoastCornerMaskBetweenDirections5And0(unsigned char* src, unsigned char* dest,
                                                           short srcStride, short destStride) {
  for (int rowDirections5And0 = 0x20; rowDirections5And0 < 0x40; ++rowDirections5And0) {
    int halfRow = (rowDirections5And0 - 0x20) / 2;
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, rowDirections5And0, 0x1f - halfRow,
                         2 + halfRow * 2);
  }
}

// FUNCTION: IMPERIALISM 0x005252d0
void TMapDialog::CopyCoastCornerMaskBetweenDirections4And5(unsigned char* src, unsigned char* dest,
                                                           short srcStride, short destStride) {
  for (int rowDirections4And5 = 0x20; rowDirections4And5 < 0x40; ++rowDirections4And5) {
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, rowDirections4And5, 0,
                         0x20 - (rowDirections4And5 - 0x20) / 2);
  }
}

// FUNCTION: IMPERIALISM 0x005254a0
void TMapDialog::CopyCoastCornerMaskBetweenDirections3And4(unsigned char* src, unsigned char* dest,
                                                           short srcStride, short destStride) {
  for (int rowDirections3And4 = 0; rowDirections3And4 < 0x20; ++rowDirections3And4) {
    CopyMapTilePixelSpan(src, dest, srcStride, destStride, rowDirections3And4, 0,
                         0x10 + rowDirections3And4 / 2);
  }
}

// Copies a 64-row tile block, 16 dwords (64 bytes) per row via two unrolled 8-dword
// stores, advancing source and destination by their own dword strides between rows.
// FUNCTION: IMPERIALISM 0x00525670
void TMapDialog::NewCopy64(unsigned char* src, unsigned char* dest, short srcStride,
                           short destStride) {
  short srcStrideDwords = static_cast<short>(srcStride / 4);
  short destStrideDwords = static_cast<short>(destStride / 4);
  int row = 0x40;
  do {
    int inner = 2;
    unsigned char* s;
    unsigned char* d;
    do {
      s = src;
      d = dest;
      CopyPixelDword(d, s);
      CopyPixelDword(d + 4, s + 4);
      CopyPixelDword(d + 8, s + 8);
      CopyPixelDword(d + 0xc, s + 0xc);
      CopyPixelDword(d + 0x10, s + 0x10);
      CopyPixelDword(d + 0x14, s + 0x14);
      CopyPixelDword(d + 0x18, s + 0x18);
      CopyPixelDword(d + 0x1c, s + 0x1c);
      inner = inner - 1;
      dest = d + 0x20;
      src = s + 0x20;
    } while (inner != 0);
    row = row - 1;
    dest = d + destStrideDwords * 4 - 0x20;
    src = s + srcStrideDwords * 4 - 0x20;
  } while (row != 0);
}

// FUNCTION: IMPERIALISM 0x00525730
void TMapDialog::ForwardProjectTileIndexToWrappedScreenOffsetByScale(int tileIndex,
                                                                     const CPoint* viewportOrigin,
                                                                     short* outVerticalOffset,
                                                                     short* outHorizontalOffset,
                                                                     int projectionScale) {
  ProjectTileIndexToWrappedScreenOffsetByScale(static_cast<short>(tileIndex), viewportOrigin,
                                               outVerticalOffset, outHorizontalOffset,
                                               static_cast<short>(projectionScale));
}
