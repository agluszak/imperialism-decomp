#pragma once

#include "game/TMinister.h"

class TGreatPower;

int AllocateWithFallbackHandler(undefined4 size);

// VTABLE: IMPERIALISM 0x00659cb0
class TForeignMinister : public TMinister {
public:
  TForeignMinister();
  void InitializeStateAndCounters();

  // TForeignMinister-introduced virtuals (vtable 0x659cb0 slots 22-39, byte 0x58-0x9c).
  // TMinister's own vtable ends at slot 21; these extend it. Slots 40-47 are NULL in orig.
  virtual void Call58();                                                               // 22 (0x58)
  virtual void MinisterSlot17();                                                       // 23 (0x5c)
  virtual void MinisterSlot18();                                                       // 24 (0x60)
  virtual void MinisterSlot19();                                                       // 25 (0x64)
  virtual void MinisterSlot1A(short arg = 0);                                          // 26 (0x68)
  virtual void MinisterSlot1B();                                                       // 27 (0x6c)
  virtual void MinisterSlot1C();                                                       // 28 (0x70)
  virtual void MinisterSlot1D();                                                       // 29 (0x74)
  virtual void MinisterSlot1E();                                                       // 30 (0x78)
  virtual void MinisterSlot1F();                                                       // 31 (0x7c)
  virtual void Call80();                                                               // 32 (0x80)
  virtual void MinisterSlot21();                                                       // 33 (0x84)
  virtual char MinisterSlot22();                                                       // 34 (0x88)
  virtual void Call8C();                                                               // 35 (0x8c)
  virtual void Call90();                                                               // 36 (0x90)
  virtual void Call94();                                                               // 37 (0x94)
  virtual void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation); // 38 (0x98)
  virtual void RecomputeOrderStateSlot9C();                                            // 39 (0x9c)

  unsigned char foreignState48[0x80 - 0x48];

  void* operator new(unsigned int size) {
    (void)size;
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(0x80));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }
};
