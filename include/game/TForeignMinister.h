#pragma once

#include "game/TMinister.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 thunk_InitializeTMinisterBaseOrderArray(void);

// VTABLE: IMPERIALISM 0x00659cb0
class TForeignMinister : public TMinister {
public:
  TForeignMinister();
  void InitializeStateAndCounters();

  void* operator new(unsigned int size) {
    (void)size;
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(0x80));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }
};
