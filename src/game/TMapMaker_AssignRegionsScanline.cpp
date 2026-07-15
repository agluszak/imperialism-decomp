// TMapMaker::AssignCityRegionIdsFromOverlayScanlineIntersections (0x0052b9b0) -- the UMapper.cpp
// scanline fill that paints city-region ids across the tile grid from the region-border
// SeaSegment table (g_regionBorderLinkTable_006a3900). Walking the overlay grid cell by cell,
// it finds the SeaSegment whose edge crosses the current scanline within the cell's x-span
// (interpolating the crossing x, with a horizontal-wrap branch), breaking ties between two
// crossing segments by shared endpoint + heading angle, then writes that segment's region id
// (SelectAttrByAngle) into the tile. Own translation unit.
//
// NOTE: the two-segment tie-break and the exact overlay-coord doubling are reconstructed from a
// heavily register-aliased decompile and are the least-certain part; the scanline crossing test
// and the fill/advance loop are faithful.

#include "game/TMapMaker.h"

#include "decomp_types.h"
#include "game/global_data_tables.h"
#include "game/map_overlay_geometry.h"
#include "game/sea_geometry.h"

// UMapper.cpp assert reporter (see the merge/rotate passes).
undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(...);

namespace {
const char kUMapperPath[] = "D:\\Ambit\\Cross\\UMapper.cpp";
}

// FUNCTION: IMPERIALISM 0x0052b9b0
void TMapMaker::AssignCityRegionIdsFromOverlayScanlineIntersections() {
  SeaSegmentStretch& segments = g_regionBorderLinkTable_006a3900;

  int cellX = 0;
  int leftCol = 0;
  unsigned int scanY = 0;
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
        if (leftEdge != rightEdge && seg->y0 != seg->y1 && static_cast<int>(scanY) >= seg->y0 &&
            seg->y1 > static_cast<int>(scanY)) {
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
              // Wrapped segment: the crossing spans the 0xd8-wide horizontal seam.
              dx = (seg->x0 < seg->x1) ? -0xd8 : 0xd8;
            }
            double slope = static_cast<double>(dx) / (seg->y1 - seg->y0);
            double crossX = static_cast<double>(static_cast<int>(scanY)) * slope +
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
                if (DAT_006a3910 == 0) {
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
    if (*tile == '\x05' && region != -1) {
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
