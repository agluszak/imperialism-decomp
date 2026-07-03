// SeapointStretch / SeaSegmentStretch -- two concrete instantiations of the project-local
// stretch<T> growable-array family used by the UMapper coastline/region builder.
//
// The single vtable slot of each (GetOrAppendUnique) is the by-value append; it was
// previously mis-attributed to TMapMaker (SetEnabled/SetState) because Ghidra merged the
// two adjacent single-slot vtables into TMapMaker's. See sea_geometry.h.

#include "game/sea_geometry.h"

#include "decomp_types.h"

// Allocator-tracked realloc (generic stub form; typed cast at the call sites).
extern undefined4 ReallocateHeapBlockWithAllocatorTracking(void);

namespace {

template <typename T> inline T* ReallocElems(T* buffer, int bytes) {
  return reinterpret_cast<T*>(reinterpret_cast<void*(__cdecl*)(void*, int)>(
      ReallocateHeapBlockWithAllocatorTracking)(buffer, bytes));
}

} // namespace

// --- SeaSegmentStretch (0x18-byte elements) --------------------------------------------

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
