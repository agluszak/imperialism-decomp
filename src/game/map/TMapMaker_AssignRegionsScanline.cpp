// TMapMaker::AssignCityRegionIdsFromOverlayScanlineIntersections (0x0052b9b0) -- the UMapper.cpp
// scanline fill that paints city-region ids across the tile grid from the region-border
// SeaSegment table (g_regionBorderLinkTable_006a3900). Walking the overlay grid cell by cell,
// it finds the SeaSegment whose edge crosses the current scanline within the cell's x-span
// (interpolating the crossing x, with a horizontal-wrap branch), breaking ties between two
// crossing segments by shared endpoint + heading angle, then writes that segment's region id
// (SelectAttrByAngle) into the tile. Own translation unit.
//
// The scanline crossing and two-segment tie-break follow the listing's integer slope and
// shared-endpoint angle comparisons; the exact overlay-coordinate interpretation remains
// provisional.

#include "game/map_ui/TMapMaker.h"

#include "decomp_types.h"
#include "game/globals/prelude.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/map/map_overlay_geometry.h"
#include "game/map/sea_geometry.h"
#include "game/gfx/ui_invalidation_guard.h"

namespace {
const char kUMapperPath[] = "D:\\Ambit\\Cross\\UMapper.cpp";
}

// FUNCTION: IMPERIALISM 0x0052b9b0
void TMapMaker::AssignCityRegionIdsFromOverlayScanlineIntersections() {
  SeaSegmentStretch& segments = g_regionBorderLinkTable_006a3900;

  int cellX = 0;
  int leftCol = 0;
  int scanY = 0;
  int firstX = -1;
  short region = -1;
  int rowBase = 0;

  do {
    SeaSegment* best = nullptr;
    unsigned int si = 0;
    if (segments.Count() != 0) {
      int leftEdge = (scanY & 1) + leftCol * 2;
      int rightEdge = (scanY & 1) + cellX * 2;
      do {
        SeaSegment* seg = segments.At(si);
        int spanLo = leftEdge;
        int spanHi = rightEdge;
        if (rightEdge < leftEdge) {
          spanLo = rightEdge;
          spanHi = leftEdge;
        }
        bool crosses = false;
        if (leftEdge != rightEdge && seg->y0 != seg->y1 && scanY >= seg->y0 && seg->y1 > scanY) {
          if (seg->x0 != seg->x1) {
            int dx;
            if (seg->wrap16 == 0) {
              dx = seg->x1 - seg->x0;
            } else {
              if (spanLo < 0x6c) {
                spanLo = spanLo + 0xd8;
              }
              if (spanHi < 0x6c) {
                spanHi = spanHi + 0xd8;
              }
              // The wrapped branch measures the crossing across the 0xd8-wide seam.
              dx = -0xd8;
            }
            int slope = dx / (seg->y1 - seg->y0);
            double crossX = static_cast<double>(scanY) * slope +
                            (static_cast<double>(seg->x0) - static_cast<double>(seg->y0) * slope);
            if (spanLo <= crossX && crossX < spanHi) {
              crosses = true;
            }
          } else if (seg->x0 >= spanLo && spanHi > seg->x0) {
            crosses = true;
          }
        }

        if (crosses) {
          if (best == nullptr) {
            best = segments.At(si);
          } else {
            SeaSegment* cur = segments.At(si);
            MapEdgePoint curStart = {cur->x0, cur->y0};
            WrapExtendedMapXCoordinateInPlace(&curStart.x);
            MapEdgePoint bestStart = {best->x0, best->y0};
            WrapExtendedMapXCoordinateInPlace(&bestStart.x);
            if (curStart.Equals(&bestStart)) {
              if (static_cast<unsigned short>(cur->angle14) <
                  static_cast<unsigned short>(best->angle14)) {
                best = segments.At(si);
              }
            } else {
              MapEdgePoint curEnd = {cur->x1, cur->y1};
              WrapExtendedMapXCoordinateInPlace(&curEnd.x);
              int endpoint[2];
              best->ExtractWrappedEndpoint(endpoint, '\0');
              MapEdgePoint bestEnd = {endpoint[0], endpoint[1]};
              if (curEnd.Equals(&bestEnd) == 0) {
                if (g_bOverlayScanlineFillAssertSuppressed == 0) {
                  TemporarilyClearAndRestoreUiInvalidationFlag(kUMapperPath, 0xda1);
                }
              } else if (static_cast<unsigned short>(best->angle14) <
                         static_cast<unsigned short>(cur->angle14)) {
                best = segments.At(si);
              }
            }
          }
        }
        si = si + 1;
      } while (si < static_cast<unsigned int>(segments.Count()));
    }

    if (best != nullptr) {
      region = static_cast<short>(best->SelectAttrByAngle());
      if (firstX < 0) {
        firstX = cellX;
      }
    }

    int col = cellX;
    if (0x6b < cellX) {
      col = cellX + -0x6c;
    }
    char* tile = mapTileGrid08 + (col + rowBase) * 0x24;
    if (*tile == kStrategicTerrainWater && region != -1) {
      tile[4] = static_cast<char>(region) + '\x17';
    }
    leftCol = col;
    cellX = col + 1;
    if (firstX == cellX) {
      leftCol = 0;
      scanY = scanY + 1;
      rowBase = rowBase + 0x6c;
      cellX = 0;
      region = -1;
      firstX = -1;
    }
    if (0x194f < rowBase) {
      return;
    }
  } while (true);
}
