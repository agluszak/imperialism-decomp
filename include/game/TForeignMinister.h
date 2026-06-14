#pragma once

#include "game/TMinister.h"

class TGreatPower;

int AllocateWithFallbackHandler(undefined4 size_bytes);

// VTABLE: IMPERIALISM 0x00659cb0
class TForeignMinister : public TMinister {
public:
  TForeignMinister();
  void InitializeStateAndCounters();

  void Call80() override;
  void Call8C() override;
  void Call90() override;
  void Call94() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
  void RecomputeOrderStateSlot9C() override;

  void* operator new(unsigned int size) {
    (void)size;
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(0x80));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }
};
