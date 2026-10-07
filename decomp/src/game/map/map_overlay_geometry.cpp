#include "game/map_domain_types.h"
#include "game/map/map_overlay_geometry.h"

#include "game/map/TMapMgr.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/map/TMapUberPicture.h"
#include "game/navy/TNavyMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/navy/TOcean.h"
#include "game/navy/TTaskForce.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/military_ui_globals.h"
#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x00508f30
void BuildHexNeighborHighlightPolygonForTile(short tileId, int compareValue) {
  short neighborTiles[6];
  TMapMgr::GetNeighborTileIDArray(tileId, neighborTiles,
                                  g_pGlobalMapState->hexNeighborWrapHorizontally);
  int screenXY[2];
  ComputeWrappedIsometricScreenOffsetFromTile(tileId, screenXY, 0x10, 0, 0);
  int baseX = static_cast<short>(
      0x31 - static_cast<int>(static_cast<float>(static_cast<short>(screenXY[0])) *
                              g_HexHighlightScreenScale));
  int baseY = static_cast<short>(
      0x2d - static_cast<int>(static_cast<float>(static_cast<short>(screenXY[1])) *
                              g_HexHighlightScreenScale));
  int rightX = baseX + 5;
  int bottomY = baseY + 5;

  TTerrainStateRecord* terrain = g_pGlobalMapState->terrainStateTable;

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

// FUNCTION: IMPERIALISM 0x005093e0
void DrawHexNeighborBorderGuidePathForTile(short tileId, int compareValue, short tileScale) {
  short neighborTiles[6];
  TMapMgr::GetNeighborTileIDArray(tileId, neighborTiles,
                                  g_pGlobalMapState->hexNeighborWrapHorizontally);
  int screenXY[2];
  ComputeWrappedIsometricScreenOffsetFromTile(tileId, screenXY, 0x10, 0, 0);

  int x0;
  int y0;
  int x1;
  int x2;
  int x3;
  int x4;
  int y1;
  int y2;
  int y3;
  int y4;
  int y5;
  int yUp;
  if (tileScale == 0x10) {
    x0 = static_cast<short>(screenXY[0]);
    y0 = static_cast<short>(screenXY[1]);
    x1 = x0 + 4;
    x2 = x0 + 8;
    x3 = x0 + 0xc;
    x4 = x0 + 0x10;
    y1 = y0 + 4;
    y2 = y0 + 8;
    y3 = y0 + 0xc;
    y4 = y0 + 0x10;
    y5 = y0 + 0x14;
    yUp = y0 - 4;
  } else {
    y0 = static_cast<short>(0x2d -
                            static_cast<int>(static_cast<float>(static_cast<short>(screenXY[1])) *
                                             g_HexHighlightScreenScale));
    x0 = static_cast<short>(0x31 -
                            static_cast<int>(static_cast<float>(static_cast<short>(screenXY[0])) *
                                             g_HexHighlightScreenScale));
    x1 = x0 + 1;
    x2 = x0 + 2;
    x3 = x0 + 4;
    x4 = x0 + 5;
    y1 = y0 + 1;
    y2 = y0 + 2;
    y3 = y0 + 4;
    y4 = y0 + 5;
    y5 = y0 + 7;
    yUp = y0 - 2;
  }

  TTerrainStateRecord* terrain = g_pGlobalMapState->terrainStateTable;

  SetQuickDrawTextOriginWithContextOffset(static_cast<short>(x2), static_cast<short>(y0));

  if (neighborTiles[5] != -1 && neighborTiles[0] != -1 &&
      terrain[neighborTiles[5]].cityRecordIndex == compareValue &&
      terrain[neighborTiles[0]].cityRecordIndex != compareValue) {
    DrawCenteredGuideLineOnMapDc(static_cast<short>(x2), static_cast<short>(yUp));
  }
  DrawCenteredGuideLineOnMapDc(static_cast<short>(x3), static_cast<short>(y0));

  if (neighborTiles[0] == -1 || neighborTiles[1] == -1 ||
      terrain[neighborTiles[0]].cityRecordIndex == compareValue ||
      terrain[neighborTiles[1]].cityRecordIndex == compareValue ||
      terrain[neighborTiles[0]].cityRecordIndex != terrain[neighborTiles[1]].cityRecordIndex) {
    DrawCenteredGuideLineOnMapDc(static_cast<short>(x4), static_cast<short>(y0));
  }
  DrawCenteredGuideLineOnMapDc(static_cast<short>(x4), static_cast<short>(y1));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(x4), static_cast<short>(y2));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(x4), static_cast<short>(y3));

  if (neighborTiles[1] == -1 || neighborTiles[2] == -1 ||
      terrain[neighborTiles[1]].cityRecordIndex == compareValue ||
      terrain[neighborTiles[2]].cityRecordIndex == compareValue ||
      terrain[neighborTiles[1]].cityRecordIndex != terrain[neighborTiles[2]].cityRecordIndex) {
    DrawCenteredGuideLineOnMapDc(static_cast<short>(x4), static_cast<short>(y4));
  }
  DrawCenteredGuideLineOnMapDc(static_cast<short>(x3), static_cast<short>(y4));

  // The bottom-centre pair is emitted in whichever order puts the in-region side first.
  int pendingX = x2;
  int pendingY = y4;
  if (neighborTiles[2] != -1 && neighborTiles[3] != -1) {
    if (terrain[neighborTiles[2]].cityRecordIndex == compareValue) {
      if (terrain[neighborTiles[3]].cityRecordIndex != compareValue) {
        DrawCenteredGuideLineOnMapDc(static_cast<short>(x2), static_cast<short>(y4));
        pendingX = x2;
        pendingY = y5;
      }
    } else if (terrain[neighborTiles[3]].cityRecordIndex == compareValue) {
      DrawCenteredGuideLineOnMapDc(static_cast<short>(x2), static_cast<short>(y5));
      pendingX = x2;
      pendingY = y4;
    }
  }
  DrawCenteredGuideLineOnMapDc(static_cast<short>(pendingX), static_cast<short>(pendingY));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(x1), static_cast<short>(y4));

  if (neighborTiles[3] == -1 || neighborTiles[4] == -1 ||
      terrain[neighborTiles[3]].cityRecordIndex == compareValue ||
      terrain[neighborTiles[4]].cityRecordIndex == compareValue ||
      terrain[neighborTiles[3]].cityRecordIndex != terrain[neighborTiles[4]].cityRecordIndex) {
    DrawCenteredGuideLineOnMapDc(static_cast<short>(x0), static_cast<short>(y4));
  }
  DrawCenteredGuideLineOnMapDc(static_cast<short>(x0), static_cast<short>(y3));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(x0), static_cast<short>(y2));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(x0), static_cast<short>(y1));

  if (neighborTiles[4] == -1 || neighborTiles[5] == -1 ||
      terrain[neighborTiles[4]].cityRecordIndex == compareValue ||
      terrain[neighborTiles[5]].cityRecordIndex == compareValue ||
      terrain[neighborTiles[4]].cityRecordIndex != terrain[neighborTiles[5]].cityRecordIndex) {
    DrawCenteredGuideLineOnMapDc(static_cast<short>(x0), static_cast<short>(y0));
  }
  DrawCenteredGuideLineOnMapDc(static_cast<short>(x1), static_cast<short>(y0));

  if (neighborTiles[5] != -1 && neighborTiles[0] != -1 &&
      terrain[neighborTiles[5]].cityRecordIndex != compareValue &&
      terrain[neighborTiles[0]].cityRecordIndex == compareValue) {
    DrawCenteredGuideLineOnMapDc(static_cast<short>(x2), static_cast<short>(yUp));
  }
  DrawCenteredGuideLineOnMapDc(static_cast<short>(x2), static_cast<short>(y0));
}

// FUNCTION: IMPERIALISM 0x00528c10
int GetNeighborTileIndexOnMap108x60(int tileIndex, int direction) {
  int col;
  if ((tileIndex / kStrategicMapColumns & 1U) == 0) {
    col = g_hexColOffsetEvenRow[direction];
  } else {
    col = g_hexColOffsetOddRow[direction];
  }
  col = tileIndex % kStrategicMapColumns + col;
  int row = tileIndex / kStrategicMapColumns + g_hexRowOffset[direction];
  if (g_pGlobalMapState->hexNeighborWrapHorizontally == '\0') {
    if (col < 0) {
      col += kStrategicMapColumns;
    } else if (col > 0x6b) {
      col -= kStrategicMapColumns;
    }
  } else {
    if (col < 0) {
      return -1;
    }
    if (col > 0x6b) {
      return -1;
    }
  }
  if (row > -1 && row < kStrategicMapRows) {
    return col + row * kStrategicMapColumns;
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x0052a6e0
int* WrapExtendedMapXCoordinateInPlace(int* x) {
  if (g_pGlobalMapState->hexNeighborWrapHorizontally == '\0') {
    int value = *x;
    if (value >= 0xd8) {
      *x = value - 0xd8;
      return x;
    }
    if (value < 0) {
      *x = value + 0xd8;
    }
  }
  return x;
}

// FUNCTION: IMPERIALISM 0x0052c990
int ConvertTileIndexToOverlayCoord216BySide(int tileIndex, char side) {
  unsigned int row = tileIndex / kStrategicMapColumns;
  int column = (row & 1) + (tileIndex % kStrategicMapColumns) * 2;
  int result = column;
  if (side == '\0') {
    result = column + 2;
    ++row;
    if (result >= 0xd8) {
      result -= 0xd8;
    }
  }
  return result + row * 216;
}

// FUNCTION: IMPERIALISM 0x0052e990
unsigned int MapEdgePoint::Equals(const MapEdgePoint* other) const {
  if (y == other->y && x == other->x) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00559a70
int __stdcall GetMapContextActionCode(short nTileIndex, int dwInputFlags) {
  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[nTileIndex];
  short actionClass = tile.tileActionState;
  if (actionClass == kMapTileActionStateNone) {
    return 0;
  }
  if (actionClass >= kMapTileActionStateBlockadingFleet &&
      actionClass <= kMapTileActionStateInvadingFleet && actionClass != kMapTileActionStateAnchor) {
    return 0xb;
  }
  if (actionClass >= kMapTileActionStateNationOrderFirst &&
      actionClass <= kMapTileActionStateNationOrderLast) {
    short ordinal = tile.tileActionOrdinal;
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
    if (g_pViewMgr->mapUberPicture->activeUnitCategoryIndex == 2) {
      activeOrderContext = g_pViewMgr->mapUberPicture->orderEntryContext;
    }
    TZone* resolvedZone = g_pActiveMapOrderContext->GetZoneAt(nTileIndex);
    return resolvedZone == activeOrderContext ? 10 : 9;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00559bd0
int __stdcall GetActiveMapOrderEntryActionCode(short nTileIndex, int dwInputFlags) {
  TTaskForce* entry = GetActiveMapOrderEntry();
  if (entry == 0) {
    return 0;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].terrainKindStorage ==
      kStrategicTerrainWater) {
    TZone* zone = g_pActiveMapOrderContext->GetZoneAt(nTileIndex);
    bool reachable = false;
    if (zone != 0 && entry->shipCountsByToolbarSlot[0] + entry->shipCountsByToolbarSlot[1] +
                             entry->shipCountsByToolbarSlot[2] +
                             entry->shipCountsByToolbarSlot[3] !=
                         0) {
      TMapOrderChildLinkNode* scan = entry->shipList;
      while (scan != 0 && scan->active == 0) {
        scan = scan->next;
      }
      if (scan != 0) {
        short minWeight = 10000;
        for (TMapOrderChildLinkNode* node = entry->shipList; node != 0; node = node->next) {
          if (node->active != 0) {
            short weight = g_NavyOrderResourceDescriptorTable[node->payload->type].Firepower();
            if (weight < minWeight) {
              minWeight = weight;
            }
          }
        }
        short distance = entry->location->GetDistanceTo(zone);
        reachable = distance <= (minWeight == 10000 ? static_cast<short>(0) : minWeight);
      }
    }
    if (reachable) {
      return entry->MouseCodeForTarget(zone);
    }
  } else {
    Province* province = GetProvinceByTileIndex(nTileIndex);
    unsigned char eligible = 0;
    if (province != 0 && entry->shipCountsByToolbarSlot[0] + entry->shipCountsByToolbarSlot[1] +
                                 entry->shipCountsByToolbarSlot[2] +
                                 entry->shipCountsByToolbarSlot[3] !=
                             0) {
      TMapOrderChildLinkNode* scan = entry->shipList;
      while (scan != 0 && scan->active == 0) {
        scan = scan->next;
      }
      if (scan != 0) {
        eligible = province->navyOrderReachable;
      }
    }
    if (eligible != 0) {
      return g_pDiplomacyTurnStateManager->AreInEstablishedWar(entry->nation,
                                                               province->ownerNationCode)
                 ? 0x10
                 : 1;
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00565d20
void ComputeWrappedIsometricScreenOffsetFromTile(int tileIndex, int* outScreenXY, int tileScale,
                                                 short originCol, short originRow) {
  int row = tileIndex / kStrategicMapColumns;
  outScreenXY[1] = row;
  int halfTileXOffset = (row & 1) == 0 ? tileScale / 2 : 0;
  outScreenXY[1] = (row - originRow) * tileScale;
  outScreenXY[0] =
      (((tileIndex - originCol) + kStrategicMapColumns) % 108) * tileScale - halfTileXOffset;
}
