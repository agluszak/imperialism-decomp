#pragma once

#include "decomp_types.h"

#include "game/stretch.h"

// stretch<SeaSegment> and stretch<Seapoint>: the coastline builder's growable arrays, each
// with a single-slot vtable whose slot is Add.

struct Seapoint {
  int coord; // linear overlay index / raw value
  int lo;    // sorted-low attribute
  int hi;    // sorted-high attribute
  int f0c;

  // Store the four dwords, ordering lo <= hi.
  void InitSorted(int value, int a, int b, int extra);
  double WrappedDeltaMetric(const Seapoint* other) const;
};

struct SeaSegment {
  short x0;   // overlay col of endpoint 0 (coord0 % 0xd8)
  short y0;   // overlay row of endpoint 0 (coord0 / 0xd8)
  short x1;   // overlay col of endpoint 1
  short y1;   // overlay row of endpoint 1
  int coord0; // linear overlay index of endpoint 0 (x0 + y0*0xd8)
  int coord1; // linear overlay index of endpoint 1
  // Attributes carried from endpoint 0; border links store the two regions.
  short attrBySide[2];
  short angle;        // heading angle (atan2 of the endpoint delta)
  unsigned char wrap; // set when the segment spans the horizontal wrap (|dx| > 0x6c)

  short& BorderX0() {
    return x0;
  }
  short& BorderY0() {
    return y0;
  }
  short& BorderX1() {
    return x1;
  }
  short& BorderY1() {
    return y1;
  }
  int& BorderReserved08() {
    return coord0;
  }
  int& BorderReserved0c() {
    return coord1;
  }
  short& BorderRegionA() {
    return attrBySide[0];
  }
  short& BorderRegionB() {
    return attrBySide[1];
  }
  short BorderX0() const {
    return x0;
  }
  short BorderY0() const {
    return y0;
  }
  short BorderX1() const {
    return x1;
  }
  short BorderY1() const {
    return y1;
  }
  short BorderRegionA() const {
    return attrBySide[0];
  }
  short BorderRegionB() const {
    return attrBySide[1];
  }

  short& AttrBySideIndex(int sideIndex) {
    return attrBySide[sideIndex];
  }

  void InitFromPoints(const Seapoint* p0, const Seapoint* p1);
  // Re-normalize endpoint order (topmost/leftmost first) and recompute the angle.
  void RecomputeEndpointsAndAngle();
  // Pick attrBySide[1] or attrBySide[0] depending on the heading angle.
  unsigned short SelectAttrByAngle() const;
  void ExtractWrappedEndpoint(int* out, char side) const;
};

IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
class SeapointStretch : public stretch<Seapoint> {};

// The SeaSegment stretch (e.g. the region-border-link table global at 0x006a3900).
class SeaSegmentStretch : public stretch<SeaSegment> {};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

ASSERT_SIZE(SeapointStretch, 0x10);
ASSERT_SIZE(SeaSegmentStretch, 0x10);
ASSERT_SIZE(Seapoint, 0x10);
ASSERT_OFFSET(Seapoint, coord, 0x00);
ASSERT_OFFSET(Seapoint, f0c, 0x0c);
ASSERT_SIZE(SeaSegment, 0x18);
ASSERT_OFFSET(SeaSegment, coord0, 0x08);
ASSERT_OFFSET(SeaSegment, angle, 0x14);

int OverlayCoordFromTileColumnRowAndSide(int column, int row, char side);

void EmitOverlaySegmentFromTileEdgeSorted(int tileIndex, char side, int a, int b, int extra);

void RebuildRegionBorderLinkLattice();

void AssignRegionIdAlongBorderSegmentChain(unsigned int index, char side, short regionId);
