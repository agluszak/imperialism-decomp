#pragma once

#include <string.h>

__inline long PointerAddressLong32(const void* pointer) {
  long bits;
  memcpy(&bits, &pointer, sizeof(bits));
  return bits;
}

__inline void* PointerFromAddressLong32(long bits) {
  void* pointer;
  memcpy(&pointer, &bits, sizeof(pointer));
  return pointer;
}
