// Free geometry helpers for the UMapper overlay grid (a 0xd8=216-wide doubled-column grid laid
// over the 0x6c=108-wide hex tile map).

#include "game/map_overlay_geometry.h"

#include "game/TGlobalMapState.h"
#include "game/TMapMgr.h"
#include "game/quickdraw_regions.h"
#include "game/TMapUberPicture.h"
#include "game/TNavyMgr.h"
#include "game/TOcean.h"
#include "game/TTaskForce.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"

// Draws the hex-cell border-highlight polygon for a tile: computes the tile's isometric
// screen position, then emits a QDFrameRect segment for each hex edge whose neighbor either
// has a different owner (owner != compareValue on both sides of the edge) or forms a
// type-5 (ocean) pairing. Neighbor tile indices [0..5] come from ComputeHexNeighborTileIndices.
// Called from TMacViewMgr's map-highlight pass. terrainStateTable owner is the +0x14 short,
// terrain type is the +0x00 byte (== 5 for ocean); both indexed by the 0x24-byte tile record.
// FUNCTION: IMPERIALISM 0x00508f30
void BuildHexNeighborHighlightPolygonForTile(short tileId, int compareValue) {
  short neighborTiles[6];
  TMapMgr::ComputeHexNeighborTileIndices(tileId, neighborTiles,
                                         *(reinterpret_cast<char*>(g_pGlobalMapState) + 0x20));
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

  unsigned char* terrain = reinterpret_cast<unsigned char*>(g_pGlobalMapState->terrainStateTable);

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

#define TERRAIN_OWNER(n) (*reinterpret_cast<short*>(terrain + (n) * 0x24 + 0x14))
#define TERRAIN_TYPE(n) (*reinterpret_cast<char*>(terrain + (n) * 0x24))

  if (neighborTiles[1] != -1 && neighborTiles[2] != -1 &&
      TERRAIN_OWNER(neighborTiles[1]) != compareValue &&
      TERRAIN_OWNER(neighborTiles[2]) == compareValue) {
    QDFrameRect(&edgeLowerRight);
  }
  if (neighborTiles[4] != -1 && neighborTiles[3] != -1 && TERRAIN_TYPE(neighborTiles[4]) == 5 &&
      TERRAIN_TYPE(neighborTiles[3]) == 5) {
    QDFrameRect(&edgeUpperLeft);
  }
  if (neighborTiles[0] != -1 && neighborTiles[1] != -1 &&
      TERRAIN_OWNER(neighborTiles[1]) != compareValue &&
      TERRAIN_OWNER(neighborTiles[0]) == compareValue) {
    QDFrameRect(&edgeCornerBR);
  }
  if (neighborTiles[4] != -1) {
    if (neighborTiles[5] != -1 && TERRAIN_TYPE(neighborTiles[4]) == 5 &&
        TERRAIN_TYPE(neighborTiles[5]) == 5) {
      QDFrameRect(&edgeCornerTL);
    }
    if (neighborTiles[3] != -1 && TERRAIN_OWNER(neighborTiles[4]) != compareValue &&
        TERRAIN_OWNER(neighborTiles[3]) == compareValue) {
      QDFrameRect(&edgeLowerLeft);
    }
  }
  if (neighborTiles[1] != -1 && neighborTiles[2] != -1 && TERRAIN_TYPE(neighborTiles[1]) == 5 &&
      TERRAIN_TYPE(neighborTiles[2]) == 5) {
    QDFrameRect(&edgeUpperRight);
  }
  if (neighborTiles[4] != -1 && neighborTiles[5] != -1 &&
      TERRAIN_OWNER(neighborTiles[4]) != compareValue &&
      TERRAIN_OWNER(neighborTiles[5]) == compareValue) {
    QDFrameRect(&edgeCornerBL);
  }
  if (neighborTiles[1] != -1 && neighborTiles[0] != -1 && TERRAIN_TYPE(neighborTiles[1]) == 5 &&
      TERRAIN_TYPE(neighborTiles[0]) == 5) {
    QDFrameRect(&edgeCornerTR);
  }

#undef TERRAIN_OWNER
#undef TERRAIN_TYPE
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
//   required_count matches (class-7), cache it in g_pCachedMapActionContext for a downstream
//   dialog branch, return class-5.
// - Class 14..21: compare the tile's resolved zone against the UI's currently-active order
//   context zone; return 10 if the same, 9 if different.
// - Otherwise (or class -1): no action (0).
// FUNCTION: IMPERIALISM 0x00559a70
int __stdcall GetMapContextActionCode(short nTileIndex, int dwInputFlags) {
  (void)dwInputFlags;
  TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[nTileIndex];
  short actionClass = static_cast<signed char>(tile.pad16);
  if (actionClass == -1) {
    return 0;
  }
  if (actionClass >= 2 && actionClass <= 6 && actionClass != 3) {
    return 0xb;
  }
  if (actionClass >= 7 && actionClass <= 0xd) {
    short ordinal = tile.tileActionOrdinal1a;
    g_pCachedMapActionContext = 0;
    if (ordinal != -1) {
      int matchIndex = 0;
      for (TTaskForce* entry = g_pNavyOrderManager->orderListHead04; entry != 0;
           entry = entry->queue_next) {
        if (entry->required_count == static_cast<short>(actionClass - 7)) {
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
  if (actionClass >= 0xe && actionClass <= 0x15) {
    TZone* activeOrderContext = 0;
    if (g_pUiRuntimeContext->mapUberPictureF0->activeUnitCategoryIndex96 == 2) {
      activeOrderContext = g_pUiRuntimeContext->mapUberPictureF0->orderEntryContext98;
    }
    TZone* resolvedZone = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    return resolvedZone == activeOrderContext ? 10 : 9;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00559dd0
unsigned short __stdcall GetMapContextActionLabelTokenByActionCode(short nTileIndex,
                                                                   int dwInputFlags) {
  return static_cast<unsigned short>(
      g_awMapContextActionLabelTokenByCommand[GetMapContextActionCode(nTileIndex, dwInputFlags)]);
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

// FUNCTION: IMPERIALISM 0x005A39A0
int ComputeHexTileDistanceFromIndices(int tileIndexA, int tileIndexB) {
  unsigned int rowA = static_cast<unsigned int>(tileIndexA / 0x1d);
  int colA = (rowA & 1U) + (tileIndexA % 0x1d) * 2;
  unsigned int rowB = static_cast<unsigned int>(tileIndexB / 0x1d);
  int colB = (rowB & 1U) + (tileIndexB % 0x1d) * 2;

  if (colB < colA) {
    colB = colA * 2 - colB;
  }
  if (static_cast<int>(rowB) < static_cast<int>(rowA)) {
    rowB = rowA * 2 - rowB;
  }

  int rowDelta = static_cast<int>(rowB - rowA);
  colA = (colB - rowDelta) - colA;
  if (0 < colA) {
    return colA / 2 + rowDelta;
  }
  return rowDelta;
}
