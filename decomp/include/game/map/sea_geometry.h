#pragma once

#include "decomp_types.h"

#include "game/stretch.h"

// The TMapMaker coastline/region builder (UMapper.cpp) keeps two project-local growable
// arrays from the stretch<T> family (see stretch.h): a stretch<SeaSegment> of 0x18-byte
// segments and a stretch<Seapoint> of 0x10-byte points. Mac CodeWarrior evidence names
// them exactly that (stretch<SeaSegment>/stretch<Seapoint> with Add/operator[]/OverStretch
// members and a SeaSegment(const Seapoint&, const Seapoint&) constructor) — i.e. NOT MFC
// CArray (CArray copy-constructs on grow; these realloc-double-or-fallback like the rest of
// the stretch family).
//
// Each has its own single-slot vtable placed in memory immediately after TMapMaker's vtable
// (0x006598f8): the SeaSegment stretch at 0x0065999c, the Seapoint stretch at 0x006599a0.
// The Ghidra extractor over-extended TMapMaker's vtable to swallow those two adjacent
// tables. The 0x0052a760/0x0052c0a0 functions are the by-value append virtual (the
// single vtable slot, modelled here as Add to match the stretch<T> template).

struct Seapoint {
  int coord00; // +0x00 linear overlay index / raw value
  int lo04;    // +0x04 sorted-low attribute
  int hi08;    // +0x08 sorted-high attribute
  int f0c;     // +0x0c

  // Store the four dwords, ordering lo04<=hi08. 0x0052b1e0.
  void InitSorted(int value, int a, int b, int extra);
  double WrappedDeltaMetric(const Seapoint* other) const;
};

struct SeaSegment {
  short x0;            // +0x00 overlay col of endpoint 0 (coord0 % 0xd8)
  short y0;            // +0x02 overlay row of endpoint 0 (coord0 / 0xd8)
  short x1;            // +0x04 overlay col of endpoint 1
  short y1;            // +0x06 overlay row of endpoint 1
  int coord0;          // +0x08 linear overlay index of endpoint 0 (x0 + y0*0xd8)
  int coord1;          // +0x0c linear overlay index of endpoint 1
  short attr10;        // +0x10 carried attribute (from endpoint 0's lo04)
  short attr12;        // +0x12 carried attribute (from endpoint 0's hi08)
  short angle14;       // +0x14 heading angle (atan2 of the endpoint delta)
  unsigned char wrap;  // +0x16 set when the segment spans the horizontal wrap (|dx| > 0x6c)
  unsigned char pad17; // +0x17

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
    return attr10;
  }
  short& BorderRegionB() {
    return attr12;
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
    return attr10;
  }
  short BorderRegionB() const {
    return attr12;
  }

  short& AttrBySideIndex(int sideIndex) {
    return (&attr10)[sideIndex];
  }

  void InitFromPoints(const Seapoint* p0, const Seapoint* p1);
  // Re-normalize endpoint order (topmost/leftmost first) and recompute the angle. 0x0052ab00.
  void RecomputeEndpointsAndAngle();
  // Pick attr12 or attr10 depending on the heading angle. 0x0052c000.
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
ASSERT_OFFSET(Seapoint, coord00, 0x00);
ASSERT_OFFSET(Seapoint, f0c, 0x0c);
ASSERT_SIZE(SeaSegment, 0x18);
ASSERT_OFFSET(SeaSegment, coord0, 0x08);
ASSERT_OFFSET(SeaSegment, angle14, 0x14);

int OverlayCoordFromTileColumnRowAndSide(int column, int row, char side);

void EmitOverlaySegmentFromTileEdgeSorted(int tileIndex, char side, int a, int b, int extra);

void RebuildRegionBorderLinkLattice();

void AssignRegionIdAlongBorderSegmentChain(unsigned int index, char side, short regionId);
