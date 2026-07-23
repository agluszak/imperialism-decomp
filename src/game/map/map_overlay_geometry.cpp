// Free geometry helpers for the UMapper overlay grid (a 0xd8=216-wide doubled-column grid laid
// over the 0x6c=108-wide hex tile map).

#include "game/map/map_overlay_geometry.h"

#include "game/map/TMapMgr.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/map/TMapUberPicture.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TOcean.h"
#include "game/navy/TTaskForce.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"

// Draws the hex-cell border-highlight polygon for a tile: computes the tile's isometric
// screen position, then emits a QDFrameRect segment for each hex edge whose neighbor either
// has a different city/region (cityRecordIndex != compareValue on both sides of the edge)
// or forms a type-5 (ocean) pairing. Neighbor tile indices [0..5] come from
// GetNeighborTileIDArray. Called from TMacViewMgr's map-highlight pass. Reads the
// typed TTerrainStateRecordView fields cityRecordIndex (+0x14) and GetTerrainKind() (+0x00,
// == 5 for ocean) directly, instead of the former raw `terrain + n*0x24 + off` casts.
// FUNCTION: IMPERIALISM 0x00508f30
void BuildHexNeighborHighlightPolygonForTile(short tileId, int compareValue) {
  short neighborTiles[6];
  TMapMgr::GetNeighborTileIDArray(tileId, neighborTiles,
                                  g_pGlobalMapState->hexNeighborWrapHorizontally20);
  int screenXY[2];
  ComputeWrappedIsometricScreenOffsetFromTile(tileId, screenXY, 0x10, 0, 0);
  int baseX = static_cast<short>(
      0x31 - static_cast<int>(static_cast<float>(static_cast<short>(screenXY[0])) *
                              g_HexHighlightScreenScale_00658640));
  int baseY = static_cast<short>(
      0x2d - static_cast<int>(static_cast<float>(static_cast<short>(screenXY[1])) *
                              g_HexHighlightScreenScale_00658640));
  int rightX = baseX + 5;
  int bottomY = baseY + 5;

  TTerrainStateRecordView* terrain = g_pGlobalMapState->terrainStateTable;

  RECT edgeTop = {baseX, baseY, rightX, bottomY};
  QDFrameRect(&edgeTop);

  RECT edgeUpperLeft = {baseX, baseY + 4, baseX + 1, bottomY};
  RECT edgeCornerTL = {baseX, baseY, baseX + 1, baseY + 1};
  RECT edgeLowerLeft = {baseX - 1, baseY + 4, baseX, bottomY};
  RECT edgeUpperRight = {baseX + 4, baseY + 4, rightX, bottomY};
  RECT edgeLowerRight = {rightX, baseY + 4, baseX + 6, bottomY};
  RECT edgeCornerBL = {baseX - 1, baseY, baseX, baseY + 1};
  RECT edgeCornerBR = {rightX, baseY, baseX + 6, baseY + 1};
  RECT edgeCornerTR = {baseX + 4, baseY, rightX, baseY + 1};

  if (neighborTiles[1] != -1 && neighborTiles[2] != -1 &&
      terrain[neighborTiles[1]].cityRecordIndex != compareValue &&
      terrain[neighborTiles[2]].cityRecordIndex == compareValue) {
    QDFrameRect(&edgeLowerRight);
  }
  if (neighborTiles[4] != -1 && neighborTiles[3] != -1 &&
      terrain[neighborTiles[4]].GetTerrainKind() == kStrategicTerrainWater &&
      terrain[neighborTiles[3]].GetTerrainKind() == kStrategicTerrainWater) {
    QDFrameRect(&edgeUpperLeft);
  }
  if (neighborTiles[0] != -1 && neighborTiles[1] != -1 &&
      terrain[neighborTiles[1]].cityRecordIndex != compareValue &&
      terrain[neighborTiles[0]].cityRecordIndex == compareValue) {
    QDFrameRect(&edgeCornerBR);
  }
  if (neighborTiles[4] != -1) {
    if (neighborTiles[5] != -1 &&
        terrain[neighborTiles[4]].GetTerrainKind() == kStrategicTerrainWater &&
        terrain[neighborTiles[5]].GetTerrainKind() == kStrategicTerrainWater) {
      QDFrameRect(&edgeCornerTL);
    }
    if (neighborTiles[3] != -1 && terrain[neighborTiles[4]].cityRecordIndex != compareValue &&
        terrain[neighborTiles[3]].cityRecordIndex == compareValue) {
      QDFrameRect(&edgeLowerLeft);
    }
  }
  if (neighborTiles[1] != -1 && neighborTiles[2] != -1 &&
      terrain[neighborTiles[1]].GetTerrainKind() == kStrategicTerrainWater &&
      terrain[neighborTiles[2]].GetTerrainKind() == kStrategicTerrainWater) {
    QDFrameRect(&edgeUpperRight);
  }
  if (neighborTiles[4] != -1 && neighborTiles[5] != -1 &&
      terrain[neighborTiles[4]].cityRecordIndex != compareValue &&
      terrain[neighborTiles[5]].cityRecordIndex == compareValue) {
    QDFrameRect(&edgeCornerBL);
  }
  if (neighborTiles[1] != -1 && neighborTiles[0] != -1 &&
      terrain[neighborTiles[1]].GetTerrainKind() == kStrategicTerrainWater &&
      terrain[neighborTiles[0]].GetTerrainKind() == kStrategicTerrainWater) {
    QDFrameRect(&edgeCornerTR);
  }
}

// FUNCTION: IMPERIALISM 0x00528c10
int GetNeighborTileIndexOnMap108x60(int tileIndex, int direction) {
  int col;
  if ((tileIndex / 0x6c & 1U) == 0) {
    col = g_hexColOffsetEvenRow_00697450[direction];
  } else {
    col = g_hexColOffsetOddRow_00697480[direction];
  }
  col = tileIndex % 0x6c + col;
  int row = tileIndex / 0x6c + g_hexRowOffset_00697468[direction];
  if (g_pGlobalMapState->hexNeighborWrapHorizontally20 == '\0') {
    if (col < 0) {
      col = col + 0x6c;
    } else if (0x6b < col) {
      col = col - 0x6c;
    }
  } else {
    if (col < 0) {
      return -1;
    }
    if (0x6b < col) {
      return -1;
    }
  }
  if (-1 < row && row < 0x3c) {
    return col + row * 0x6c;
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x0052a6e0
void WrapExtendedMapXCoordinateInPlace(int* x) {
  if (g_pGlobalMapState->hexNeighborWrapHorizontally20 == '\0') {
    int value = *x;
    if (value >= 0xd8) {
      *x = value - 0xd8;
      return;
    }
    if (value < 0) {
      *x = value + 0xd8;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0052c990
int ConvertTileIndexToOverlayCoord216BySide(int tileIndex, char side) {
  unsigned int row = tileIndex / 0x6c;
  int column = (row & 1) + (tileIndex % 0x6c) * 2;
  int result = column;
  if (side == '\0') {
    result = column + 2;
    row = row + 1;
    if (result >= 0xd8) {
      result -= 0xd8;
    }
  }
  return result + row * 0xd8;
}

// FUNCTION: IMPERIALISM 0x0052e990
unsigned int MapEdgePoint::Equals(const MapEdgePoint* other) const {
  if (y == other->y && x == other->x) {
    return 1;
  }
  return 0;
}

// Maps a clicked tile to a map-context action code used by the map-order handlers.
// - Tile action class 2..6 (excluding 3): open the entry-order dialog (11).
// - Class 7..13: walk g_pNavyOrderManager's TTaskForce queue for the ordinal-th entry whose
//   nation matches (class-7), cache it in g_pCachedMapActionContext for a downstream
//   dialog branch, return class-5.
// - Class 14..21: compare the tile's resolved zone against the UI's currently-active order
//   context zone; return 10 if the same, 9 if different.
// - Otherwise (or class -1): no action (0).
// FUNCTION: IMPERIALISM 0x00559a70
int __stdcall GetMapContextActionCode(short nTileIndex, int dwInputFlags) {
  (void)dwInputFlags;
  TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[nTileIndex];
  short actionClass = tile.tileActionState16;
  if (actionClass == kMapTileActionStateNone) {
    return 0;
  }
  if (actionClass >= kMapTileActionStateBlockadingFleet &&
      actionClass <= kMapTileActionStateInvadingFleet && actionClass != kMapTileActionStateAnchor) {
    return 0xb;
  }
  if (actionClass >= kMapTileActionStateNationOrderFirst &&
      actionClass <= kMapTileActionStateNationOrderLast) {
    short ordinal = tile.tileActionOrdinal1a;
    g_pCachedMapActionContext = 0;
    if (ordinal != -1) {
      int matchIndex = 0;
      for (TTaskForce* entry = g_pNavyOrderManager->orderQueueHead; entry != 0;
           entry = entry->nextForce) {
        if (entry->nation ==
            static_cast<short>(actionClass - kMapTileActionStateNationOrderFirst)) {
          if (matchIndex == ordinal) {
            g_pCachedMapActionContext = entry;
            break;
          }
          ++matchIndex;
        }
      }
    }
    return actionClass - 5;
  }
  if (actionClass >= kMapTileActionStateLinkedZoneFirst &&
      actionClass <= kMapTileActionStateLinkedZoneLast) {
    TZone* activeOrderContext = 0;
    if (g_pUiRuntimeContext->mapUberPictureF0->activeUnitCategoryIndex96 == 2) {
      activeOrderContext = g_pUiRuntimeContext->mapUberPictureF0->orderEntryContext98;
    }
    TZone* resolvedZone = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    return resolvedZone == activeOrderContext ? 10 : 9;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00565d20
void ComputeWrappedIsometricScreenOffsetFromTile(int tileIndex, int* outScreenXY, int tileScale,
                                                 short originCol, short originRow) {
  int row = tileIndex / 0x6c;
  outScreenXY[1] = row;
  int halfTileXOffset = (row & 1) == 0 ? tileScale / 2 : 0;
  outScreenXY[1] = (row - originRow) * tileScale;
  outScreenXY[0] = (((tileIndex - originCol) + 0x6c) % 0x6c) * tileScale - halfTileXOffset;
}
