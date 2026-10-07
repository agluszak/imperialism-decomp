#include "game/map_domain_types.h"
#include "game/map/sea_geometry.h"

#include <math.h>
#include <stdio.h>

#include "decomp_types.h"
#include "game/map/TMapMgr.h"
#include "game/map/map_overlay_geometry.h"
#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"

namespace {

const double kSeaAngleScale = 11733.857334728455;

} // namespace

// FUNCTION: IMPERIALISM 0x0052a850
void LoadRegionBorderLinkTableFromCoordsFile() {
  unsigned int index = 0;
  if (g_regionBorderLinkTable.data != 0) {
    free(g_regionBorderLinkTable.Detach());
  }

  FILE* file = fopen("coords.txt", "r");
  while (!feof(file)) {
    int column0;
    int row0;
    int column1;
    int row1;
    fscanf(file, "%d %d %d %d", &column0, &row0, &column1, &row1);

    int clampedRow1 = row1;
    if (clampedRow1 < 0) {
      clampedRow1 = 0;
    }
    if (clampedRow1 > kStrategicMapRows) {
      clampedRow1 = 0x3c;
    }
    int coord1 = (clampedRow1 & 1) + column1 * 2;
    if (coord1 >= 0xd8) {
      coord1 -= 0xd8;
    }
    coord1 = coord1 + clampedRow1 * 0xd8;

    int clampedRow0 = row0;
    if (clampedRow0 < 0) {
      clampedRow0 = 0;
    }
    if (clampedRow0 > kStrategicMapRows) {
      clampedRow0 = 0x3c;
    }
    int coord0 = (clampedRow0 & 1) + column0 * 2;
    if (coord0 >= 0xd8) {
      coord0 -= 0xd8;
    }
    coord0 = coord0 + clampedRow0 * 0xd8;

    SeaSegment segment;
    segment.angle = 0;
    segment.coord1 = coord1;
    segment.coord0 = coord0;
    segment.x0 = static_cast<short>(coord0 % 0xd8);
    segment.y0 = static_cast<short>(coord0 / 0xd8);
    segment.x1 = static_cast<short>(coord1 % 0xd8);
    segment.y1 = static_cast<short>(coord1 / 0xd8);
    segment.attrBySide[0] = -1;
    segment.attrBySide[1] = -1;
    segment.RecomputeEndpointsAndAngle();
    g_regionBorderLinkTable[index] = segment;
    ++index;
  }
  fclose(file);
}

// FUNCTION: IMPERIALISM 0x0052ab00
void SeaSegment::RecomputeEndpointsAndAngle() {
  if (y1 < y0 || (y0 == y1 && x1 < x0)) {
    short nx0 = x1;
    short ny0 = y1;
    short nx1 = x0;
    short ny1 = y0;
    x0 = nx0;
    y0 = ny0;
    x1 = nx1;
    y1 = ny1;
    coord0 = x0 + y0 * 0xd8;
    coord1 = x1 + y1 * 0xd8;
  }
  int adx = x0 - x1;
  wrap = (adx < 0 ? -adx : adx) > 0x6c;
  int dx;
  int dy;
  if (wrap && x0 < x1) {
    dx = (x1 - x0) - 0xd8;
    dy = y1 - y0;
  } else {
    dx = x1 - x0;
    dy = y1 - y0;
  }
  angle = static_cast<short>(
      static_cast<int>(atan2(static_cast<double>(dy), static_cast<double>(dx)) * kSeaAngleScale));
}

// FUNCTION: IMPERIALISM 0x0052ac40
void RebuildRegionBorderLinkLattice() {
  unsigned int index = 0;
  if (g_regionBorderLinkTable.Data() != 0) {
    free(g_regionBorderLinkTable.Detach());
  }

  int column = 2;
  int edgeBase = 0x1c;
  do {
    int row = -6;
    do {
      // Every other lattice row is staggered the other way, in both axes at once.
      int rowStagger;
      int columnStagger;
      if ((((row + 6) / 0xc) & 1) == 0) {
        columnStagger = 6;
        rowStagger = 2;
      } else {
        columnStagger = 0;
        rowStagger = -2;
      }

      int rowAhead = rowStagger + row;
      int clampedAhead = rowAhead;
      if (clampedAhead < 0) {
        clampedAhead = 0;
      }
      if (clampedAhead > 0x3c) {
        clampedAhead = 0x3c;
      }
      int coordAhead = (clampedAhead & 1) + column * 2 + 0xc;
      if (coordAhead >= 0xd8) {
        coordAhead -= 0xd8;
      }
      coordAhead = coordAhead + clampedAhead * 0xd8;

      int rowBehind = row - rowStagger;
      int clampedBehind = rowBehind;
      if (clampedBehind < 0) {
        clampedBehind = 0;
      }
      if (clampedBehind > 0x3c) {
        clampedBehind = 0x3c;
      }
      int coordBehind = (clampedBehind & 1) + column * 2;
      if (coordBehind >= 0xd8) {
        coordBehind -= 0xd8;
      }
      coordBehind = coordBehind + clampedBehind * 0xd8;

      SeaSegment cellSegment;
      cellSegment.angle = 0;
      cellSegment.coord1 = coordAhead;
      cellSegment.coord0 = coordBehind;
      cellSegment.x0 = static_cast<short>(coordBehind % 0xd8);
      cellSegment.y0 = static_cast<short>(coordBehind / 0xd8);
      cellSegment.x1 = static_cast<short>(coordAhead % 0xd8);
      cellSegment.y1 = static_cast<short>(coordAhead / 0xd8);
      cellSegment.attrBySide[0] = -1;
      cellSegment.attrBySide[1] = -1;
      cellSegment.RecomputeEndpointsAndAngle();
      g_regionBorderLinkTable[index] = cellSegment;
      ++index;

      int clampedEdgeRow = rowBehind;
      if (clampedEdgeRow < 0) {
        clampedEdgeRow = 0;
      }
      if (clampedEdgeRow > kStrategicMapRows) {
        clampedEdgeRow = 0x3c;
      }
      Seapoint edgePoint;
      edgePoint.f0c = 4;
      int edgeCoord = (clampedEdgeRow & 1) + edgeBase;
      if (edgeCoord >= 0xd8) {
        edgeCoord -= 0xd8;
      }
      edgePoint.coord00 = edgeCoord + clampedEdgeRow * 0xd8;
      edgePoint.lo04 = -1;
      edgePoint.hi08 = -1;

      int clampedSpanRow = rowAhead;
      if (clampedSpanRow < 0) {
        clampedSpanRow = 0;
      }
      if (clampedSpanRow > kStrategicMapRows) {
        clampedSpanRow = 0x3c;
      }
      int spanCoord = (clampedSpanRow & 1) + column * 2 + 0xc;
      if (spanCoord >= 0xd8) {
        spanCoord -= 0xd8;
      }
      Seapoint spanPoint;
      spanPoint.InitSorted(spanCoord + clampedSpanRow * 0xd8, -1, -1, 1);
      SeaSegment spanSegment;
      spanSegment.InitFromPoints(&spanPoint, &edgePoint);
      g_regionBorderLinkTable[index] = spanSegment;
      ++index;

      int laneColumn = columnStagger + column;
      Seapoint laneStart;
      laneStart.InitSorted(OverlayCoordFromTileColumnRowAndSide(laneColumn, row + 0xa, 1), -1, -1,
                           5);
      Seapoint laneEnd;
      laneEnd.InitSorted(OverlayCoordFromTileColumnRowAndSide(laneColumn, row + 0xa - 8, 1), -1, -1,
                         2);
      SeaSegment laneSegment;
      laneSegment.InitFromPoints(&laneEnd, &laneStart);
      g_regionBorderLinkTable[index] = laneSegment;
      ++index;

      row += 0xc;
    } while (row < kStrategicMapRows);
    column += 0xc;
    edgeBase += 0x18;
  } while (column - 2 < 0x6c);

  int edgeColumn = 8;
  do {
    Seapoint topPoint;
    topPoint.InitSorted(OverlayCoordFromTileColumnRowAndSide(edgeColumn, 1000, 1), -1, -1, 4);
    Seapoint topNeighbor;
    topNeighbor.InitSorted(OverlayCoordFromTileColumnRowAndSide(edgeColumn - 6, 1000, 1), -1, -1,
                           1);
    SeaSegment topSegment;
    topSegment.InitFromPoints(&topNeighbor, &topPoint);
    g_regionBorderLinkTable[index] = topSegment;
    ++index;

    Seapoint bottomPoint;
    bottomPoint.InitSorted(OverlayCoordFromTileColumnRowAndSide(edgeColumn + 6, 1000, 1), -1, -1,
                           4);
    Seapoint bottomNeighbor;
    bottomNeighbor.InitSorted(OverlayCoordFromTileColumnRowAndSide(edgeColumn, 1000, 1), -1, -1, 1);
    SeaSegment bottomSegment;
    bottomSegment.InitFromPoints(&bottomNeighbor, &bottomPoint);
    g_regionBorderLinkTable[index] = bottomSegment;
    ++index;

    edgeColumn += 0xc;
  } while (edgeColumn - 8 < 0x6c);
}

// FUNCTION: IMPERIALISM 0x0052b160
int OverlayCoordFromTileColumnRowAndSide(int column, int row, char side) {
  if (row < 0) {
    row = 0;
  }
  if (row > kStrategicMapRows) {
    row = 0x3c;
  }
  int overlayX = (row & 1) + column * 2;
  if (side == '\0') {
    ++row;
    overlayX += 2;
    if (overlayX >= 0xd8) {
      overlayX -= 0xd8;
    }
  } else if (overlayX >= 0xd8) {
    overlayX -= 0xd8;
  }
  return overlayX + row * 0xd8;
}

// FUNCTION: IMPERIALISM 0x0052b1e0
void Seapoint::InitSorted(int value, int a, int b, int extra) {
  coord00 = value;
  f0c = extra;
  lo04 = a;
  hi08 = b;
  if (a > b) {
    lo04 = b;
    hi08 = a;
  }
}

// FUNCTION: IMPERIALISM 0x0052b220
void SeaSegment::InitFromPoints(const Seapoint* p0, const Seapoint* p1) {
  angle = 0;
  int c0 = p0->coord00;
  coord0 = c0;
  coord1 = p1->coord00;
  int c1 = coord1;
  x0 = static_cast<short>(c0 % 0xd8);
  y0 = static_cast<short>(c0 / 0xd8);
  x1 = static_cast<short>(c1 % 0xd8);
  y1 = static_cast<short>(c1 / 0xd8);
  attrBySide[0] = static_cast<short>(p0->lo04);
  attrBySide[1] = static_cast<short>(p0->hi08);
  if (y1 < y0 || (y0 == y1 && x1 < x0)) {
    short nx0 = x1;
    short ny0 = y1;
    short nx1 = x0;
    short ny1 = y0;
    x0 = nx0;
    y0 = ny0;
    x1 = nx1;
    y1 = ny1;
    coord0 = x0 + y0 * 0xd8;
    coord1 = x1 + y1 * 0xd8;
  }
  int adx = x0 - x1;
  wrap = (adx < 0 ? -adx : adx) > 0x6c;
  int dx;
  int dy;
  if (wrap && x0 < x1) {
    dx = (x1 - x0) - 0xd8;
    dy = y1 - y0;
  } else {
    dx = x1 - x0;
    dy = y1 - y0;
  }
  angle = static_cast<short>(
      static_cast<int>(atan2(static_cast<double>(dy), static_cast<double>(dx)) * kSeaAngleScale));
}

// FUNCTION: IMPERIALISM 0x0052b520
void AssignRegionIdAlongBorderSegmentChain(unsigned int index, char side, short regionId) {
  while (true) {
    int sideIndex = side == '\0';
    SeaSegment* record = g_regionBorderLinkTable.At(index);
    g_regionBorderLinkTable[index];
    if (record->AttrBySideIndex(sideIndex) != -1) {
      return;
    }
    record->AttrBySideIndex(sideIndex) = regionId;

    unsigned short bestTurn = 0xffff;
    unsigned int bestIndex = 0xffffffff;

    short reversedAngle;
    const short* baseAnglePtr;
    if (side != '\0') {
      baseAnglePtr = &g_regionBorderLinkTable.At(index)->angle;
    } else {
      reversedAngle = static_cast<short>(g_regionBorderLinkTable.At(index)->angle - 0x7001);
      baseAnglePtr = &reversedAngle;
    }
    short baseAngle = *baseAnglePtr;

    SeaSegment* current = g_regionBorderLinkTable.At(index);
    int endpoint0[2];
    int endpoint1[2];
    int* joint;
    if (side != '\0') {
      endpoint0[0] = current->x0;
      endpoint0[1] = current->y0;
      joint = endpoint0;
    } else {
      endpoint1[0] = current->x1;
      endpoint1[1] = current->y1;
      joint = endpoint1;
    }
    joint = WrapExtendedMapXCoordinateInPlace(joint);
    int jointX = joint[0];
    int jointY = joint[1];

    unsigned int candidate = 0;
    if (g_regionBorderLinkTable.count != 0) {
      do {
        if (candidate != index) {
          SeaSegment* other = g_regionBorderLinkTable.At(candidate);
          int otherStart[2];
          otherStart[0] = other->x0;
          otherStart[1] = other->y0;
          int* wrappedStart = WrapExtendedMapXCoordinateInPlace(otherStart);
          if (jointY == wrappedStart[1] && jointX == wrappedStart[0]) {
            unsigned short turn = static_cast<unsigned short>(
                g_regionBorderLinkTable.At(candidate)->angle - baseAngle);
            if (turn <= bestTurn) {
              bestTurn = turn;
              bestIndex = candidate;
              side = '\0';
            }
          }

          SeaSegment* otherAgain = g_regionBorderLinkTable.At(candidate);
          int otherEnd[2];
          otherEnd[0] = otherAgain->x1;
          otherEnd[1] = otherAgain->y1;
          int* wrappedEnd = WrapExtendedMapXCoordinateInPlace(otherEnd);
          if (jointY == wrappedEnd[1] && jointX == wrappedEnd[0]) {
            unsigned short turn = static_cast<unsigned short>(
                g_regionBorderLinkTable.At(candidate)->angle - baseAngle - 0x7001);
            if (turn <= bestTurn) {
              bestTurn = turn;
              bestIndex = candidate;
              side = '\x01';
            }
          }
        }
        ++candidate;
      } while (candidate < static_cast<unsigned int>(g_regionBorderLinkTable.count));
    }
    index = bestIndex;
  }
}

// FUNCTION: IMPERIALISM 0x0052bef0
void SeaSegment::ExtractWrappedEndpoint(int* out, char side) const {
  if (side != '\0') {
    int cx = x0;
    short cy = y0;
    if (g_pGlobalMapState->hexNeighborWrapHorizontally == '\0') {
      if (0xd7 < cx) {
        out[0] = cx - 0xd8;
        out[1] = cy;
        return;
      }
      if (cx < 0) {
        cx += 0xd8;
      }
    }
    out[0] = cx;
    out[1] = cy;
    return;
  }
  int cx = x1;
  short cy = y1;
  if (g_pGlobalMapState->hexNeighborWrapHorizontally == '\0') {
    if (cx < 0xd8) {
      if (cx < 0) {
        cx += 0xd8;
      }
    } else {
      cx -= 0xd8;
    }
  }
  out[0] = cx;
  out[1] = cy;
}

// FUNCTION: IMPERIALISM 0x0052c000
unsigned short SeaSegment::SelectAttrByAngle() const {
  if (static_cast<unsigned short>(angle) < 0x8fff) {
    return static_cast<unsigned short>(attrBySide[1]);
  }
  return static_cast<unsigned short>(attrBySide[0]);
}

// FUNCTION: IMPERIALISM 0x0052ca20
void EmitOverlaySegmentFromTileEdgeSorted(int tileIndex, char side, int a, int b, int extra) {
  unsigned int row = tileIndex / kStrategicMapColumns;
  int overlayX = (row & 1) + (tileIndex % kStrategicMapColumns) * 2;
  if (side == '\0') {
    overlayX += 2;
    ++row;
    if (overlayX >= 0xd8) {
      overlayX -= 0xd8;
    }
  }
  int coord = overlayX + row * 0xd8;
  int lo = a;
  int hi = b;
  if (a > b) {
    lo = b;
    hi = a;
  }
  Seapoint pt;
  pt.coord00 = coord;
  pt.lo04 = lo;
  pt.hi08 = hi;
  pt.f0c = extra;
  stretch<Seapoint>* table = &g_seapointQuadTable;
  table->Add(pt);
}

// FUNCTION: IMPERIALISM 0x0052d030
double Seapoint::WrappedDeltaMetric(const Seapoint* other) const {
  int thisCoordinate = coord00;
  int otherCoordinate = other->coord00;
  int rowDelta = thisCoordinate / 0xd8 - otherCoordinate / 0xd8;
  if (rowDelta < 0) {
    rowDelta = -rowDelta;
  }
  int colDelta = ((thisCoordinate % 0xd8 - otherCoordinate % 0xd8) + 0xd8) % 0xd8;
  if (0x6c < colDelta) {
    colDelta = 0xd7 - colDelta;
  }
  return sqrt(static_cast<double>(colDelta * colDelta * rowDelta * rowDelta));
}
