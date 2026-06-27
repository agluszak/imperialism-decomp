#pragma once

#include "game/TMinister.h"


// AI interior minister branch.
// VTABLE: IMPERIALISM 0x00650808
class TInteriorMinister : public TMinister {
public:
  TInteriorMinister();

  DECLARE_DYNCREATE(TInteriorMinister)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  short DispatchNationStateEventCode10(short nationSlot) override;
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  virtual void MinisterSlot12();
  virtual void Call4C();
  virtual void MinisterSlot14();
  virtual void Call54();
  // Slots 0x16-0x1f: TInteriorMinister's own new virtuals (real vtable 0x650808 is
  // 32 slots, 0x00-0x1f). TCityInteriorMinister inherits 0x16-0x19 and overrides
  // 0x1a-0x1f.
  virtual void InteriorSlot16(); // 0x16 0x4be480
  virtual void InteriorSlot17(); // 0x17 0x4be4c0
  virtual void InteriorSlot18(); // 0x18 0x4be650
  virtual void InteriorSlot19(); // 0x19 0x4be690
  virtual void InteriorSlot1A(); // 0x1a 0x4be3f0
  virtual void InteriorSlot1B(); // 0x1b 0x4be410
  virtual void InteriorSlot1C(); // 0x1c 0x4be430
  virtual void InteriorSlot1D(); // 0x1d 0x4be150
  virtual void InteriorSlot1E(); // 0x1e 0x4be170
  virtual void InteriorSlot1F(); // 0x1f 0x4be190
};
