#pragma once

#include "decomp_types.h"

// 0x005e7fc0 — realloc-family growth used by every stretch mutator.
#include <stdlib.h>

// Project-local growable array template. Mac CodeWarrior symbols expose this family as
// stretch<T> with Add/operator[]/OverStretch members; the Windows TZone evidence shows
// a polymorphic 0x10-byte layout: vfptr, data, capacity, count.
//
// Only Add is a real vtable slot: TZoneSecondaryNeighborStretch's original
// vtable (0x0065c748) is confirmed exactly 1 slot long (the very next vtable,
// TZonePrimaryNeighborStretch's at 0x0065c74c, starts 4 bytes later). Concrete TZone
// specializations override that one slot to add uniqueness; all ordinary stretches use
// the generic virtual Add below.
// Confirmed 1-slot vtable (TZoneSecondaryNeighborStretch's orig vtable at 0x0065c748 is
// exactly 1 slot; see below) — no destructor slot in any instantiation.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
template <typename T> class stretch {
public:
  stretch() : data(0), capacity(0), count(0) {}
  stretch(int initialCapacity)
      : data(static_cast<T*>(realloc(0, static_cast<size_t>(initialCapacity) * sizeof(T)))),
        capacity(initialCapacity), count(0) {}
  // Non-virtual on purpose (see IMPERIALISM_*_INTENTIONAL_NON_VIRTUAL_DTOR above): frees
  // the growable buffer allocated by OverStretch/SetCapacity (realloc-family growth,
  // so release via the matching free(), not
  // delete[]). Ground truth: TZone::~TZone (0x5627a0) frees primaryNeighbors/
  // secondaryNeighbors this same way as part of member teardown.
  // Retained, unreferenced VC5 copies of this inline template destructor.
  // SYNTHETIC: IMPERIALISM 0x0055eaa0
  // stretch<TZone*>::~stretch
  // SYNTHETIC: IMPERIALISM 0x0055eb70
  // stretch<Province*>::~stretch
  ~stretch() {
    if (data != 0) {
      free(data);
    }
  }
  virtual T* Add(T value) {
    int index = count;
    T& slot = (*this)[static_cast<unsigned int>(index)];
    slot = value;
    return &slot;
  }

  int GetSize() const {
    return count;
  }
  // Raw backing buffer. Used where the original hands out the accumulated storage
  // pointer directly (e.g. a stretch<char> string-builder returning its buffer).
  T* RawData() const {
    return data;
  }
  T GetAt(int index) const {
    return data[index];
  }
  T& ElementAt(int index) {
    return data[index];
  }
  T* FindEntry(T value);
  bool ContainsEntry(T value);

  // Grow the backing store to cover requestedCount elements. All stretch
  // instantiations use the same double-capacity request and exact-size fallback;
  // sizeof(T) is the only specialization-dependent part.
  void OverStretch(unsigned int requestedCount) {
    unsigned int doubledCapacity = requestedCount * 2;
    if (doubledCapacity > 0x7fffffffU) {
      doubledCapacity = 0x7fffffffU;
    }
    void* grownBuffer = realloc(data, static_cast<size_t>(requestedCount) * sizeof(T) * 2);
    if (grownBuffer == 0) {
      data = static_cast<T*>(realloc(data, static_cast<size_t>(requestedCount) * sizeof(T)));
      capacity = static_cast<int>(requestedCount);
    } else {
      data = static_cast<T*>(grownBuffer);
      capacity = static_cast<int>(doubledCapacity);
    }
  }

  // Mac oracle: stretch<T>::operator[](unsigned int) — index access that grows the
  // buffer on overrun (same realloc-with-halving-fallback shape as the Add bodies in
  // TZone.cpp) and stretches `count` up to cover the touched slot. Always inlined by
  // MSVC500 (ground truth: the read loop of TZone::ComputeMapActionContextNodeValue-
  // Average, 0x0055f140).
  T& operator[](unsigned int index) {
    if (index >= static_cast<unsigned int>(capacity)) {
      OverStretch(index + 1);
    }
    // `index >= count` rather than `count <= index`: the original's inlined copies compare
    // the index register against the count global in that order.
    if (index >= static_cast<unsigned int>(count)) {
      count = index + 1;
    }
    return data[index];
  }

  // Reallocate the backing store to an exact element capacity without changing the
  // logical count. The original stretch<char> uses this when preparing a reusable
  // opcode buffer whose append cursor is managed by its owning record.
  void SetCapacity(unsigned int requestedCapacity) {
    data = static_cast<T*>(realloc(data, static_cast<size_t>(requestedCapacity) * sizeof(T)));
    capacity = static_cast<int>(requestedCapacity);
  }

  // Release unused tail capacity while preserving the current elements and count.
  void Compact() {
    if (count < capacity) {
      data = static_cast<T*>(realloc(data, static_cast<size_t>(count) * sizeof(T)));
      capacity = count;
    }
  }

  // Return a slot only when it is already part of the logical array.
  T* At(unsigned int index) {
    if (index < static_cast<unsigned int>(count)) {
      return &data[index];
    }
    return 0;
  }

  // Transfer ownership of the backing store and reset this collection to its
  // default empty state.
  T* Detach() {
    T* detached = data;
    data = 0;
    capacity = 0;
    count = 0;
    return detached;
  }

  // Clear the logical contents while retaining the reusable allocation.
  void RemoveAll() {
    count = 0;
  }

  T* Data() {
    return data;
  }
  const T* Data() const {
    return data;
  }
  int Capacity() const {
    return capacity;
  }
  int Count() const {
    return count;
  }

  // Public because a caller compiled under `#pragma inline_depth(0)` (see the
  // big-functions skill) cannot use the accessors above without emitting a call the
  // original does not have. The accessors stay the normal way to read these.
public:
  T* data;      // +0x04
  int capacity; // +0x08
  int count;    // +0x0c
};

// VC5 eagerly checks member bodies written inside the class template. Keep the
// equality-dependent lookup out of line so it is instantiated only for element
// types that actually use it (currently the two pointer stretches); geometry
// records do not need or define operator==.
template <typename T> T* stretch<T>::FindEntry(T value) {
  unsigned int entryCount = static_cast<unsigned int>(count);
  for (unsigned int index = 0; index < entryCount; ++index) {
    if (data[index] == value) {
      return &data[index];
    }
  }
  return 0;
}

template <typename T> bool stretch<T>::ContainsEntry(T value) {
  return FindEntry(value) != 0;
}
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR
