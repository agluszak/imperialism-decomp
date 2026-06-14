#pragma once

#include "game/TMinister.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// VTABLE: IMPERIALISM 0x006549b0
class TDefenseMinister : public TMinister {
public:
  TDefenseMinister();
  void InitializeBaseOrderArrayMetrics();

  void Call4C() override;

  void* operator new(unsigned int size) {
    (void)size;
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(0x94));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }
};
