#pragma once

#include "decomp_types.h"

#include <stdlib.h>

IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
template <typename T> class stretch {
public:
  stretch() : data(0), capacity(0), count(0) {}
  stretch(int initialCapacity) : data(0), capacity(0), count(0) {
    if (0 < initialCapacity) {
      data = static_cast<T*>(realloc(0, static_cast<size_t>(initialCapacity) * sizeof(T)));
      capacity = initialCapacity;
    }
  }
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

  T& operator[](unsigned int index) {
    if (index >= static_cast<unsigned int>(capacity)) {
      OverStretch(index + 1);
    }
    if (index >= static_cast<unsigned int>(count)) {
      count = index + 1;
    }
    return data[index];
  }

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

  T* Detach() {
    T* detached = data;
    data = 0;
    capacity = 0;
    count = 0;
    return detached;
  }

  // IFuzzySet the logical contents while retaining the reusable allocation.
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

  T* data;      // +0x04
  int capacity; // +0x08
  int count;    // +0x0c
};

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
