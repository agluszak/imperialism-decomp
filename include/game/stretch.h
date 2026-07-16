#pragma once

#include <cstdlib>

#include "decomp_types.h"

// 0x005e7fc0 — realloc-family growth used by every stretch mutator (legacy bridge
// form shared with the out-of-line Add bodies in TZone.cpp; retire together).
undefined4 ReallocateHeapBlockWithAllocatorTracking(void);

// Project-local growable array template. Mac CodeWarrior symbols expose this family as
// stretch<T> with Add/operator[]/OverStretch members; the Windows TZone evidence shows
// a polymorphic 0x10-byte layout: vfptr, data, capacity, count.
//
// Only GetOrAppendUnique is a real vtable slot: TZoneSecondaryNeighborStretch's orig
// vtable (0x0065c748) is confirmed exactly 1 slot long (the very next vtable,
// TZonePrimaryNeighborStretch's at 0x0065c74c, starts 4 bytes later). Add is always
// called on the concrete `TZone{Primary,Secondary}NeighborStretch` type directly
// (TZone.h: primaryNeighbors.Add(...)/secondaryNeighbors.Add(...)), never through a
// `stretch<T,Tag>*` base pointer, so it is declared here as an ordinary (non-virtual,
// unimplemented) member that each instantiation hides with its own definition.
// Confirmed 1-slot vtable (TZoneSecondaryNeighborStretch's orig vtable at 0x0065c748 is
// exactly 1 slot; see below) — no destructor slot in any instantiation.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
template <typename T, typename Tag> class stretch {
public:
  stretch() : data(0), capacity(0), count(0) {}
  // Non-virtual on purpose (see IMPERIALISM_*_INTENTIONAL_NON_VIRTUAL_DTOR above): frees
  // the growable buffer allocated by EnsureCapacityAtLeast/ResizePointerArrayCapacityBy-
  // RequestedCount (realloc-family growth, so release via the matching free(), not
  // delete[]). Ground truth: TZone::~TZone (0x5627a0) frees primaryNeighbors/
  // secondaryNeighbors this same way as part of member teardown.
  ~stretch() {
    if (data != 0) {
      free(data);
    }
  }
  virtual T* GetOrAppendUnique(T value) = 0;
  void Add(T value);

  int GetSize() const {
    return count;
  }
  T GetAt(int index) const {
    return data[index];
  }
  T& ElementAt(int index) {
    return data[index];
  }
  // Mac oracle: stretch<T>::operator[](unsigned int) — index access that grows the
  // buffer on overrun (same realloc-with-halving-fallback shape as the Add bodies in
  // TZone.cpp) and stretches `count` up to cover the touched slot. Always inlined by
  // MSVC500 (ground truth: the read loop of TZone::ComputeMapActionContextNodeValue-
  // Average, 0x0055f140).
  T& operator[](unsigned int index) {
    if (index >= static_cast<unsigned int>(capacity)) {
      unsigned int doubledCapacity = (index + 1) * 2;
      if (doubledCapacity > 0x7fffffffU) {
        doubledCapacity = 0x7fffffffU;
      }
      void* grownBuffer = reinterpret_cast<void*(__cdecl*)(void*, int)>(
          ReallocateHeapBlockWithAllocatorTracking)(data, (index + 1) * 8);
      if (grownBuffer == 0) {
        data = static_cast<T*>(reinterpret_cast<void*(__cdecl*)(void*, int)>(
            ReallocateHeapBlockWithAllocatorTracking)(data, (index + 1) * 4));
        capacity = index + 1;
      } else {
        data = static_cast<T*>(grownBuffer);
        capacity = static_cast<int>(doubledCapacity);
      }
    }
    if (static_cast<unsigned int>(count) <= index) {
      count = index + 1;
    }
    return data[index];
  }

  T*& Data() {
    return data;
  }
  int& Capacity() {
    return capacity;
  }
  int& Count() {
    return count;
  }

  void EnsureFirstSlotAllocated();

protected:
  T* data;      // +0x04
  int capacity; // +0x08
  int count;    // +0x0c
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR
