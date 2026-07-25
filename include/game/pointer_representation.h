#pragma once

#include <string.h>

// Imperialism's Win32 build uses 32-bit object pointers. This makes the original's
// unsigned pointer-address ordering explicit without treating an object as an integer.
__inline unsigned int PointerAddressBits32(const void* pointer) {
  unsigned int bits;
  memcpy(&bits, &pointer, sizeof(bits));
  return bits;
}
