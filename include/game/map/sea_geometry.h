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
// tables, which is why 0x0052a760/0x0052c0a0 were previously mis-attributed as
// TMapMaker::SetEnabled/SetState. They are in fact the by-value append virtual (the single
// vtable slot, modelled here as Add to match the stretch<T> template).

// A 0x10-byte map point / edge record. The two middle dwords are kept sorted (lo <= hi) by
// InitSorted. The append virtual copies all four dwords by value.
struct Seapoint {
  int coord00; // +0x00 linear overlay index / raw value
  int lo04;    // +0x04 sorted-low attribute
  int hi08;    // +0x08 sorted-high attribute
  int f0c;     // +0x0c

  // Store the four dwords, ordering lo04<=hi08. 0x0052b1e0.
  void InitSorted(int value, int a, int b, int extra);
  // Wrapped overlay-grid distance metric to another point (sqrt of colDelta^2*rowDelta^2,
  // horizontal delta wrapped to the 0xd8-wide grid). 0x0052d030.
  double WrappedDeltaMetric(const Seapoint* other) const;
};

// A 0x18-byte coastline overlay segment (Mac evidence: SeaSegment(const Seapoint&, const
// Seapoint&)). Endpoints are the two overlay-grid points (0xd8=216-wide grid); the segment
// is normalized so endpoint 0 is topmost/leftmost, then a heading angle is computed. The
// append virtual copies all six dwords by value.
struct SeaSegment {
  short x0;             // +0x00 overlay col of endpoint 0 (coord0 % 0xd8)
  short y0;             // +0x02 overlay row of endpoint 0 (coord0 / 0xd8)
  short x1;             // +0x04 overlay col of endpoint 1
  short y1;             // +0x06 overlay row of endpoint 1
  int coord0;           // +0x08 linear overlay index of endpoint 0 (x0 + y0*0xd8)
  int coord1;           // +0x0c linear overlay index of endpoint 1
  short attr10;         // +0x10 carried attribute (from endpoint 0's lo04)
  short attr12;         // +0x12 carried attribute (from endpoint 0's hi08)
  short angle14;        // +0x14 heading angle (atan2 of the endpoint delta)
  unsigned char wrap16; // +0x16 set when the segment spans the horizontal wrap (|dx| > 0x6c)
  unsigned char pad17;  // +0x17

  // Build the segment from two Seapoints' linear coords, normalize endpoint order and
  // recompute the heading angle. 0x0052b220.
  void InitFromPoints(const Seapoint* p0, const Seapoint* p1);
  // Re-normalize endpoint order (topmost/leftmost first) and recompute the angle. 0x0052ab00.
  void RecomputeEndpointsAndAngle();
  // Pick attr12 or attr10 depending on the heading angle. 0x0052c000.
  unsigned short SelectAttrByAngle() const;
  // Write endpoint 1 (side 0) or endpoint 0 (side != 0) as [x,y] into out, applying the
  // horizontal wrap when the map wraps. 0x0052bef0.
  void ExtractWrappedEndpoint(int* out, char side) const;
};

// The Seapoint stretch. Vtable is adjacent to TMapMaker's (0x006599a0); left unannotated
// because it overlaps TMapMaker's vtable data region — the append is paired by its own
// // FUNCTION: address marker instead.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
class SeapointStretch : public stretch<Seapoint> {};

// The SeaSegment stretch (e.g. the region-border-link table global at 0x006a3900).
class SeaSegmentStretch : public stretch<SeaSegment> {};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

ASSERT_SIZE(SeapointStretch, 0x10);
ASSERT_SIZE(SeaSegmentStretch, 0x10);

// Convert a tile index + edge side to an overlay coord, sort the two attribute values, and
// append the resulting Seapoint to the overlay-quad table global (0x006a3478). 0x0052ca20.
void EmitOverlaySegmentFromTileEdgeSorted(int tileIndex, char side, int a, int b, int extra);
