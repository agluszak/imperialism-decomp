#pragma once

#include "decomp_types.h"

// Project-local growable array template. Mac CodeWarrior symbols expose this family as
// stretch<T> with Add/operator[]/OverStretch members; the Windows TZone evidence shows
// a polymorphic 0x10-byte layout: vfptr, data, capacity, count.
template <typename T, typename Tag>
class stretch {
public:
  stretch() : data(0), capacity(0), count(0) {}
  virtual T* GetOrAppendUnique(T value) = 0;
  virtual void Add(T value) = 0;

  int GetSize() const { return count; }
  T GetAt(int index) const { return data[index]; }
  T& ElementAt(int index) { return data[index]; }

  T*& Data() { return data; }
  int& Capacity() { return capacity; }
  int& Count() { return count; }

  void EnsureFirstSlotAllocated();

protected:
  T* data;      // +0x04
  int capacity; // +0x08
  int count;    // +0x0c
};
