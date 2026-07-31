// SeapointStretch / SeaSegmentStretch -- two concrete instantiations of the project-local
// stretch<T> growable-array family used by the UMapper coastline/region builder.
//
// The single vtable slot of each (Add) is the by-value append. The two adjacent
// single-slot vtables are distinct from TMapMaker's. See sea_geometry.h.

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

// Segment heading angle scale (original double at 0x006598d8): atan2(dy,dx) is scaled into
// the 16-bit angle stored in SeaSegment::angle14. Referenced by both InitFromPoints and
// RecomputeEndpointsAndAngle, matching the single shared constant in the original.
const double kSeaAngleScale = 11733.857334728455;

} // namespace

// Functions are emitted in ascending original-address order (decomplint requirement), so
// the Seapoint/SeaSegment record methods interleave with the two stretch arrays' methods.

// TEMPLATE: IMPERIALISM 0x0052a760
// ?Add@?$stretch@USeaSegment@@@@UAEPAUSeaSegment@@U2@@Z

// Debug/authoring path: rebuild the region-border segment lattice from a "coords.txt"
// file of "<col0> <row0> <col1> <row1>" lines instead of the generated lattice
// (RebuildRegionBorderLinkLattice). Rows clamp to [0, 0x3c] and columns wrap at the
// 0xd8-wide overlay grid, the same conventions the generated path uses. The original
// checks neither the fopen result nor the fscanf field count.
// FUNCTION: IMPERIALISM 0x0052a850
void LoadRegionBorderLinkTableFromCoordsFile() {
  unsigned int index = 0;
  if (g_regionBorderLinkTable_006a3900.data != 0) {
    free(g_regionBorderLinkTable_006a3900.Detach());
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
    if (clampedRow1 > 0x3c) {
      clampedRow1 = 0x3c;
    }
    int coord1 = (clampedRow1 & 1) + column1 * 2;
    if (coord1 >= 0xd8) {
      coord1 = coord1 - 0xd8;
    }
    coord1 = coord1 + clampedRow1 * 0xd8;

    int clampedRow0 = row0;
    if (clampedRow0 < 0) {
      clampedRow0 = 0;
    }
    if (clampedRow0 > 0x3c) {
      clampedRow0 = 0x3c;
    }
    int coord0 = (clampedRow0 & 1) + column0 * 2;
    if (coord0 >= 0xd8) {
      coord0 = coord0 - 0xd8;
    }
    coord0 = coord0 + clampedRow0 * 0xd8;

    SeaSegment segment;
    segment.angle14 = 0;
    segment.coord1 = coord1;
    segment.coord0 = coord0;
    segment.x0 = static_cast<short>(coord0 % 0xd8);
    segment.y0 = static_cast<short>(coord0 / 0xd8);
    segment.x1 = static_cast<short>(coord1 % 0xd8);
    segment.y1 = static_cast<short>(coord1 / 0xd8);
    segment.attr10 = -1;
    segment.attr12 = -1;
    segment.RecomputeEndpointsAndAngle();
    g_regionBorderLinkTable_006a3900[index] = segment;
    index = index + 1;
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
  wrap16 = (adx < 0 ? -adx : adx) > 0x6c;
  int dx;
  int dy;
  if (wrap16 && x0 < x1) {
    dx = (x1 - x0) - 0xd8;
    dy = y1 - y0;
  } else {
    dx = x1 - x0;
    dy = y1 - y0;
  }
  angle14 = static_cast<short>(
      static_cast<int>(atan2(static_cast<double>(dy), static_cast<double>(dx)) * kSeaAngleScale));
}

// Rebuild the global region-border segment lattice (0x006a3900) from scratch. The old
// backing store is detached and freed, then the lattice is walked column by column with a
// row stagger that alternates every other lattice row: each cell appends three SeaSegments
// -- one built field-by-field and normalized in place, two built from Seapoint pairs
// through InitFromPoints -- and a final pass closes the lattice along the map's vertical
// edges using the row-1000 sentinel (clamped to the last row by the coord helper).
//
// Rows are clamped to [0, 0x3c] and overlay columns wrap at the 0xd8-wide grid, the same
// conventions OverlayCoordFromTileColumnRowAndSide applies.
// The original expands stretch<SeaSegment>::operator[] inline only at the first of the
// five append sites below and calls the out-of-line copy at the other four; VC5's inline
// budget is exhausted by this body's size. Suspending automatic expansion for this one
// function reproduces the four out-of-line calls.
IMPERIALISM_BEGIN_DISABLE_AUTOMATIC_INLINING
#pragma inline_depth(0)
// FUNCTION: IMPERIALISM 0x0052ac40
void RebuildRegionBorderLinkLattice() {
  unsigned int index = 0;
  if (g_regionBorderLinkTable_006a3900.Data() != 0) {
    free(g_regionBorderLinkTable_006a3900.Detach());
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
        coordAhead = coordAhead - 0xd8;
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
        coordBehind = coordBehind - 0xd8;
      }
      coordBehind = coordBehind + clampedBehind * 0xd8;

      SeaSegment cellSegment;
      cellSegment.angle14 = 0;
      cellSegment.coord1 = coordAhead;
      cellSegment.coord0 = coordBehind;
      cellSegment.x0 = static_cast<short>(coordBehind % 0xd8);
      cellSegment.y0 = static_cast<short>(coordBehind / 0xd8);
      cellSegment.x1 = static_cast<short>(coordAhead % 0xd8);
      cellSegment.y1 = static_cast<short>(coordAhead / 0xd8);
      cellSegment.attr10 = -1;
      cellSegment.attr12 = -1;
      cellSegment.RecomputeEndpointsAndAngle();
      g_regionBorderLinkTable_006a3900[index] = cellSegment;
      index = index + 1;

      // The cell's second segment spans from the tile-edge point on the region column
      // over to the staggered neighbour.
      int clampedEdgeRow = rowBehind;
      if (clampedEdgeRow < 0) {
        clampedEdgeRow = 0;
      }
      if (clampedEdgeRow > 0x3c) {
        clampedEdgeRow = 0x3c;
      }
      Seapoint edgePoint;
      edgePoint.f0c = 4;
      int edgeCoord = (clampedEdgeRow & 1) + edgeBase;
      if (edgeCoord >= 0xd8) {
        edgeCoord = edgeCoord - 0xd8;
      }
      edgePoint.coord00 = edgeCoord + clampedEdgeRow * 0xd8;
      edgePoint.lo04 = -1;
      edgePoint.hi08 = -1;

      int clampedSpanRow = rowAhead;
      if (clampedSpanRow < 0) {
        clampedSpanRow = 0;
      }
      if (clampedSpanRow > 0x3c) {
        clampedSpanRow = 0x3c;
      }
      int spanCoord = (clampedSpanRow & 1) + column * 2 + 0xc;
      if (spanCoord >= 0xd8) {
        spanCoord = spanCoord - 0xd8;
      }
      Seapoint spanPoint;
      spanPoint.InitSorted(spanCoord + clampedSpanRow * 0xd8, -1, -1, 1);
      SeaSegment spanSegment;
      spanSegment.InitFromPoints(&spanPoint, &edgePoint);
      g_regionBorderLinkTable_006a3900[index] = spanSegment;
      index = index + 1;

      // The third segment runs down the staggered column between two tile edges eight
      // rows apart.
      int laneColumn = columnStagger + column;
      Seapoint laneStart;
      laneStart.InitSorted(OverlayCoordFromTileColumnRowAndSide(laneColumn, row + 0xa, 1), -1, -1,
                           5);
      Seapoint laneEnd;
      laneEnd.InitSorted(OverlayCoordFromTileColumnRowAndSide(laneColumn, row + 0xa - 8, 1), -1, -1,
                         2);
      SeaSegment laneSegment;
      laneSegment.InitFromPoints(&laneEnd, &laneStart);
      g_regionBorderLinkTable_006a3900[index] = laneSegment;
      index = index + 1;

      row = row + 0xc;
    } while (row < 0x3c);
    column = column + 0xc;
    edgeBase = edgeBase + 0x18;
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
    g_regionBorderLinkTable_006a3900[index] = topSegment;
    index = index + 1;

    Seapoint bottomPoint;
    bottomPoint.InitSorted(OverlayCoordFromTileColumnRowAndSide(edgeColumn + 6, 1000, 1), -1, -1,
                           4);
    Seapoint bottomNeighbor;
    bottomNeighbor.InitSorted(OverlayCoordFromTileColumnRowAndSide(edgeColumn, 1000, 1), -1, -1, 1);
    SeaSegment bottomSegment;
    bottomSegment.InitFromPoints(&bottomNeighbor, &bottomPoint);
    g_regionBorderLinkTable_006a3900[index] = bottomSegment;
    index = index + 1;

    edgeColumn = edgeColumn + 0xc;
  } while (edgeColumn - 8 < 0x6c);
}
#pragma inline_depth()
IMPERIALISM_END_DISABLE_AUTOMATIC_INLINING

// FUNCTION: IMPERIALISM 0x0052b160
int OverlayCoordFromTileColumnRowAndSide(int column, int row, char side) {
  if (row < 0) {
    row = 0;
  }
  if (row > 0x3c) {
    row = 0x3c;
  }
  int overlayX = (row & 1) + column * 2;
  if (side == '\0') {
    row = row + 1;
    overlayX = overlayX + 2;
    if (overlayX >= 0xd8) {
      overlayX = overlayX - 0xd8;
    }
  } else if (overlayX >= 0xd8) {
    overlayX = overlayX - 0xd8;
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
  angle14 = 0;
  int c0 = p0->coord00;
  coord0 = c0;
  coord1 = p1->coord00;
  int c1 = coord1;
  x0 = static_cast<short>(c0 % 0xd8);
  y0 = static_cast<short>(c0 / 0xd8);
  x1 = static_cast<short>(c1 % 0xd8);
  y1 = static_cast<short>(c1 / 0xd8);
  attr10 = static_cast<short>(p0->lo04);
  attr12 = static_cast<short>(p0->hi08);
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
  wrap16 = (adx < 0 ? -adx : adx) > 0x6c;
  int dx;
  int dy;
  if (wrap16 && x0 < x1) {
    dx = (x1 - x0) - 0xd8;
    dy = y1 - y0;
  } else {
    dx = x1 - x0;
    dy = y1 - y0;
  }
  angle14 = static_cast<short>(
      static_cast<int>(atan2(static_cast<double>(dy), static_cast<double>(dx)) * kSeaAngleScale));
}

// TEMPLATE: IMPERIALISM 0x0052b3e0
// ?OverStretch@?$stretch@USeaSegment@@@@QAEXI@Z

// TEMPLATE: IMPERIALISM 0x0052b460
// ??A?$stretch@USeaSegment@@@@QAEAAUSeaSegment@@I@Z

// TEMPLATE: IMPERIALISM 0x0052b500
// stretch::Detach

// Flood a region id along a chain of border segments. Starting from one segment/edge-side,
// stamp the side's carried attribute with regionId, then find the segment whose matching
// endpoint coincides (after horizontal map wrap) and whose heading turns least, and repeat
// from there. Stops when the next side is already stamped.
//
// Both parameters are re-assigned per hop, which is why they are locals rather than a
// recursion: the original mutates its own argument slots and jumps back to the top.
// FUNCTION: IMPERIALISM 0x0052b520
void AssignRegionIdAlongBorderSegmentChain(unsigned int index, char side, short regionId) {
  while (true) {
    int sideIndex = side == '\0';
    // The record is taken before the slot is stretched, and the stretch's result is
    // discarded -- the original reads through the pre-stretch pointer.
    SeaSegment* record = g_regionBorderLinkTable_006a3900.At(index);
    g_regionBorderLinkTable_006a3900[index];
    if (record->AttrBySideIndex(sideIndex) != -1) {
      return;
    }
    record->AttrBySideIndex(sideIndex) = regionId;

    unsigned short bestTurn = 0xffff;
    unsigned int bestIndex = 0xffffffff;

    // Heading to measure the other segments' turn against. Coming in on side 0 the chain
    // arrives from the opposite direction, so the heading is rotated half a turn.
    short reversedAngle;
    const short* baseAnglePtr;
    if (side != '\0') {
      baseAnglePtr = &g_regionBorderLinkTable_006a3900.At(index)->angle14;
    } else {
      reversedAngle =
          static_cast<short>(g_regionBorderLinkTable_006a3900.At(index)->angle14 - 0x7001);
      baseAnglePtr = &reversedAngle;
    }
    short baseAngle = *baseAnglePtr;

    // The endpoint the chain continues from: endpoint 0 when arriving on side 1, endpoint 1
    // when arriving on side 0.
    SeaSegment* current = g_regionBorderLinkTable_006a3900.At(index);
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
    if (g_regionBorderLinkTable_006a3900.count != 0) {
      do {
        if (candidate != index) {
          SeaSegment* other = g_regionBorderLinkTable_006a3900.At(candidate);
          int otherStart[2];
          otherStart[0] = other->x0;
          otherStart[1] = other->y0;
          int* wrappedStart = WrapExtendedMapXCoordinateInPlace(otherStart);
          if (jointY == wrappedStart[1] && jointX == wrappedStart[0]) {
            unsigned short turn = static_cast<unsigned short>(
                g_regionBorderLinkTable_006a3900.At(candidate)->angle14 - baseAngle);
            if (turn <= bestTurn) {
              bestTurn = turn;
              bestIndex = candidate;
              side = '\0';
            }
          }

          SeaSegment* otherAgain = g_regionBorderLinkTable_006a3900.At(candidate);
          int otherEnd[2];
          otherEnd[0] = otherAgain->x1;
          otherEnd[1] = otherAgain->y1;
          int* wrappedEnd = WrapExtendedMapXCoordinateInPlace(otherEnd);
          if (jointY == wrappedEnd[1] && jointX == wrappedEnd[0]) {
            unsigned short turn = static_cast<unsigned short>(
                g_regionBorderLinkTable_006a3900.At(candidate)->angle14 - baseAngle - 0x7001);
            if (turn <= bestTurn) {
              bestTurn = turn;
              bestIndex = candidate;
              side = '\x01';
            }
          }
        }
        candidate = candidate + 1;
      } while (candidate < static_cast<unsigned int>(g_regionBorderLinkTable_006a3900.count));
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
        cx = cx + 0xd8;
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
        cx = cx + 0xd8;
      }
    } else {
      cx = cx - 0xd8;
    }
  }
  out[0] = cx;
  out[1] = cy;
}

// FUNCTION: IMPERIALISM 0x0052c000
unsigned short SeaSegment::SelectAttrByAngle() const {
  if (static_cast<unsigned short>(angle14) < 0x8fff) {
    return static_cast<unsigned short>(attr12);
  }
  return static_cast<unsigned short>(attr10);
}

// TEMPLATE: IMPERIALISM 0x0052c030
// stretch::At

// --- SeapointStretch (0x10-byte elements) ----------------------------------------------

// TEMPLATE: IMPERIALISM 0x0052c0a0
// ?Add@?$stretch@USeapoint@@@@UAEPAUSeapoint@@U2@@Z

// TEMPLATE: IMPERIALISM 0x0052ca00
// stretch::Detach

// FUNCTION: IMPERIALISM 0x0052ca20
void EmitOverlaySegmentFromTileEdgeSorted(int tileIndex, char side, int a, int b, int extra) {
  unsigned int row = tileIndex / 0x6c;
  int overlayX = (row & 1) + (tileIndex % 0x6c) * 2;
  if (side == '\0') {
    overlayX = overlayX + 2;
    row = row + 1;
    if (overlayX >= 0xd8) {
      overlayX = overlayX - 0xd8;
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
  // Dispatch through the stretch<Seapoint> base so the append goes through the vtable slot
  // (the original calls it indirectly), rather than being devirtualized to a direct call.
  stretch<Seapoint>* table = &g_seapointQuadTable_006a3478;
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

// TEMPLATE: IMPERIALISM 0x0052d0d0
// ?OverStretch@?$stretch@USeapoint@@@@QAEXI@Z

// TEMPLATE: IMPERIALISM 0x0052d150
// ??A?$stretch@USeapoint@@@@QAEAAUSeapoint@@I@Z

// TEMPLATE: IMPERIALISM 0x0052e310
// stretch::SetCapacity
