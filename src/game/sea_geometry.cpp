// SeapointStretch / SeaSegmentStretch -- two concrete instantiations of the project-local
// stretch<T> growable-array family used by the UMapper coastline/region builder.
//
// The single vtable slot of each (GetOrAppendUnique) is the by-value append; it was
// previously mis-attributed to TMapMaker (SetEnabled/SetState) because Ghidra merged the
// two adjacent single-slot vtables into TMapMaker's. See sea_geometry.h.

#include "game/sea_geometry.h"

#include <math.h>

#include "decomp_types.h"

// Allocator-tracked realloc (generic stub form; typed cast at the call sites).
extern undefined4 ReallocateHeapBlockWithAllocatorTracking(void);

namespace {

template <typename T> inline T* ReallocElems(T* buffer, int bytes) {
  return reinterpret_cast<T*>(reinterpret_cast<void*(__cdecl*)(void*, int)>(
      ReallocateHeapBlockWithAllocatorTracking)(buffer, bytes));
}

// Segment heading angle scale (original double at 0x006598d8): atan2(dy,dx) is scaled into
// the 16-bit angle stored in SeaSegment::angle14. Referenced by both InitFromPoints and
// RecomputeEndpointsAndAngle, matching the single shared constant in the original.
const double kSeaAngleScale = 11733.857334728455;

} // namespace

// Functions are emitted in ascending original-address order (decomplint requirement), so
// the Seapoint/SeaSegment record methods interleave with the two stretch arrays' methods.

// FUNCTION: IMPERIALISM 0x0052a760
SeaSegment* SeaSegmentStretch::GetOrAppendUnique(SeaSegment value) {
  unsigned int index = count;
  if (index >= static_cast<unsigned int>(capacity)) {
    int want = index + 1;
    unsigned int newCapacity = want * 2;
    if (newCapacity > 0x7fffffff) {
      newCapacity = 0x7fffffff;
    }
    SeaSegment* grown = ReallocElems(data, want * 0x30);
    if (grown == nullptr) {
      data = ReallocElems(data, want * 0x18);
      capacity = want;
    } else {
      data = grown;
      capacity = newCapacity;
    }
  }
  if (index >= static_cast<unsigned int>(count)) {
    count = index + 1;
  }
  SeaSegment* slot = &data[index];
  *slot = value;
  return slot;
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
  wrap16 = static_cast<unsigned char>((adx < 0 ? -adx : adx) > 0x6c);
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
  wrap16 = static_cast<unsigned char>((adx < 0 ? -adx : adx) > 0x6c);
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

// FUNCTION: IMPERIALISM 0x0052b3e0
void SeaSegmentStretch::OverStretch(unsigned int newCount) {
  unsigned int newCapacity = newCount * 2;
  if (newCapacity > 0x7fffffff) {
    newCapacity = 0x7fffffff;
  }
  SeaSegment* grown = ReallocElems(data, newCount * 0x30);
  if (grown == nullptr) {
    data = ReallocElems(data, newCount * 0x18);
    capacity = newCount;
    return;
  }
  data = grown;
  capacity = newCapacity;
}

// FUNCTION: IMPERIALISM 0x0052b460
SeaSegment* SeaSegmentStretch::operator[](unsigned int index) {
  if (index >= static_cast<unsigned int>(capacity)) {
    int want = index + 1;
    unsigned int newCapacity = want * 2;
    if (newCapacity > 0x7fffffff) {
      newCapacity = 0x7fffffff;
    }
    SeaSegment* grown = ReallocElems(data, want * 0x30);
    if (grown == nullptr) {
      data = ReallocElems(data, want * 0x18);
      capacity = want;
    } else {
      data = grown;
      capacity = newCapacity;
    }
  }
  if (index >= static_cast<unsigned int>(count)) {
    count = index + 1;
  }
  return &data[index];
}

// FUNCTION: IMPERIALISM 0x0052b500
void* SeaSegmentStretch::Detach() {
  void* detached = data;
  data = nullptr;
  capacity = 0;
  count = 0;
  return detached;
}

// FUNCTION: IMPERIALISM 0x0052c000
unsigned short SeaSegment::SelectAttrByAngle() const {
  if (static_cast<unsigned short>(angle14) < 0x8fff) {
    return static_cast<unsigned short>(attr12);
  }
  return static_cast<unsigned short>(attr10);
}

// FUNCTION: IMPERIALISM 0x0052c030
SeaSegment* SeaSegmentStretch::At(unsigned int index) {
  if (index < static_cast<unsigned int>(count)) {
    return &data[index];
  }
  return nullptr;
}

// --- SeapointStretch (0x10-byte elements) ----------------------------------------------

// FUNCTION: IMPERIALISM 0x0052c0a0
Seapoint* SeapointStretch::GetOrAppendUnique(Seapoint value) {
  unsigned int index = count;
  if (index >= static_cast<unsigned int>(capacity)) {
    int want = index + 1;
    unsigned int newCapacity = want * 2;
    if (newCapacity > 0x7fffffff) {
      newCapacity = 0x7fffffff;
    }
    Seapoint* grown = ReallocElems(data, want * 0x20);
    if (grown == nullptr) {
      data = ReallocElems(data, want * 0x10);
      capacity = want;
    } else {
      data = grown;
      capacity = newCapacity;
    }
  }
  if (index >= static_cast<unsigned int>(count)) {
    count = index + 1;
  }
  Seapoint* slot = &data[index];
  *slot = value;
  return slot;
}

// FUNCTION: IMPERIALISM 0x0052ca00
void* SeapointStretch::Detach() {
  void* detached = data;
  data = nullptr;
  capacity = 0;
  count = 0;
  return detached;
}

// FUNCTION: IMPERIALISM 0x0052d0d0
void SeapointStretch::OverStretch(unsigned int newCount) {
  unsigned int newCapacity = newCount * 2;
  if (newCapacity > 0x7fffffff) {
    newCapacity = 0x7fffffff;
  }
  Seapoint* grown = ReallocElems(data, newCount * 0x20);
  if (grown == nullptr) {
    data = ReallocElems(data, newCount * 0x10);
    capacity = newCount;
    return;
  }
  data = grown;
  capacity = newCapacity;
}

// FUNCTION: IMPERIALISM 0x0052d150
Seapoint* SeapointStretch::operator[](unsigned int index) {
  if (index >= static_cast<unsigned int>(capacity)) {
    int want = index + 1;
    unsigned int newCapacity = want * 2;
    if (newCapacity > 0x7fffffff) {
      newCapacity = 0x7fffffff;
    }
    Seapoint* grown = ReallocElems(data, want * 0x20);
    if (grown == nullptr) {
      data = ReallocElems(data, want * 0x10);
      capacity = want;
    } else {
      data = grown;
      capacity = newCapacity;
    }
  }
  if (index >= static_cast<unsigned int>(count)) {
    count = index + 1;
  }
  return &data[index];
}

// SeaSegmentStretch::ReallocExact (0x0052e310) is emitted last so this file's // FUNCTION:
// markers stay in ascending address order (it sits above the Seapoint methods
// 0x0052c0a0..0x0052d150).
// FUNCTION: IMPERIALISM 0x0052e310
void SeaSegmentStretch::ReallocExact(int newCount) {
  data = ReallocElems(data, newCount * 0x18);
  capacity = newCount;
}
