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
  // Two stack args (RET 0x8; Ghidra reads two shorts). slot 0x12 0x4be450
  virtual void MinisterSlot12(short arg1, short arg2);
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
  // One stack arg each (base bodies are bare RET 0x4 no-ops; the
  // TCityInteriorMinister overrides read it as a short).
  virtual void InteriorSlot1A(short arg); // 0x1a 0x4be3f0
  virtual void InteriorSlot1B(short arg); // 0x1b 0x4be410
  virtual void InteriorSlot1C(short arg); // 0x1c 0x4be430
  virtual short InteriorSlot1D(int arg);  // 0x1d 0x4be150 — returns arg
  virtual short InteriorSlot1E(int arg);  // 0x1e 0x4be170 — returns arg
  virtual void InteriorSlot1F(int arg);   // 0x1f 0x4be190 — no-op
};
