#pragma once

#include "decomp_types.h"

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
template <typename T, typename Tag> class stretch {
public:
  stretch() : data(0), capacity(0), count(0) {}
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
