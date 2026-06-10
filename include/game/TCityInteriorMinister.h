#pragma once

#include "game/TMinister.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// VTABLE: IMPERIALISM 0x00659c00 (base minister table until interior slots are recovered)
class TCityInteriorMinister : public TMinister {
public:
  TCityInteriorMinister();

  void* operator new(unsigned int size) {
    (void)size;
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(0x1c4));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }
};
