#pragma once

#include "game/TMinister.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

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
