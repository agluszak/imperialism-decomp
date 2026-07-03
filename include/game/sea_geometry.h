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
// vtable slot, modelled here as GetOrAppendUnique to match the stretch<T> template).

struct SeapointTag;
struct SeaSegmentTag;

// A 0x10-byte map point. Field semantics are not yet recovered; the append virtual copies
// all four dwords by value.
struct Seapoint {
  int f00; // +0x00
  int f04; // +0x04
  int f08; // +0x08
  int f0c; // +0x0c
};

// A 0x18-byte coastline segment (Mac evidence: constructed from two Seapoints). The append
// virtual copies all six dwords by value; MSVC emits the original's 6-iteration dword copy.
struct SeaSegment {
  int f00; // +0x00
  int f04; // +0x04
  int f08; // +0x08
  int f0c; // +0x0c
  int f10; // +0x10
  int f14; // +0x14
};

// The Seapoint stretch. Vtable is adjacent to TMapMaker's (0x006599a0); left unannotated
// because it overlaps TMapMaker's vtable data region — the append is paired by its own
// // FUNCTION: address marker instead.
class SeapointStretch : public stretch<Seapoint, SeapointTag> {
public:
  // The single vtable slot: append `value` at the end, growing on demand. 0x0052c0a0.
  Seapoint* GetOrAppendUnique(Seapoint value) override;
  // Non-virtual helpers (paired by address marker, called on the concrete type).
  void OverStretch(unsigned int newCount);  // 0x0052d0d0
  Seapoint* operator[](unsigned int index); // 0x0052d150
};

// The SeaSegment stretch (e.g. the region-border-link table global at 0x006a3900).
class SeaSegmentStretch : public stretch<SeaSegment, SeaSegmentTag> {
public:
  // The single vtable slot: append `value` at the end, growing on demand. 0x0052a760.
  SeaSegment* GetOrAppendUnique(SeaSegment value) override;
  // Non-virtual helpers (paired by address marker, called on the concrete type).
  void OverStretch(unsigned int newCount);    // 0x0052b3e0
  SeaSegment* operator[](unsigned int index); // 0x0052b460
  void* Detach();                             // 0x0052b500
  void ReallocExact(int newCount);            // 0x0052e310
};

ASSERT_SIZE(SeapointStretch, 0x10);
ASSERT_SIZE(SeaSegmentStretch, 0x10);
