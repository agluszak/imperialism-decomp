#pragma once

#include "game/TMinister.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// VTABLE: IMPERIALISM 0x006549b0
class TDefenseMinister : public TMinister {
public:
  TDefenseMinister();
  void InitializeBaseOrderArrayMetrics();

  CRuntimeClass* GetRuntimeClass() const override; // slot 0 (0x4ec0c0)
  // Class-specific overrides of TMinister base slots (5,6,10,18,19,20,21).
  void SerializeTMinisterBaseOrderArrayHeader(TStream* archive) override; // 5 (0x4ec1d0)
  void Call18(int arg1 = 0) override;                                     // 6 (0x4ec2f0)
  void MinisterSlot0A() override;                                         // 10 (0x4ec3d0)
  void MinisterSlot12() override;                                         // 18 (0x4ec450)
  void Call4C() override;                                                 // 19 (0x4ec4c0)
  void MinisterSlot14() override;                                         // 20 (0x4ec540)
  void Call54() override;                                                 // 21 (0x4ecbb0)

  // TDefenseMinister-introduced extension (vtable 0x6549b0 slots 22-24, byte 0x58-0x60).
  // Slots 25-29 are NULL/abstract trailing slots in orig (reccmp drops them); not declared.
  // TNapoleonMinister's vtable begins at 0x654a28 (slot 30).
  virtual void DefenseSlot16(); // 22 (0x58) 0x4ecf20
  virtual void DefenseSlot17(); // 23 (0x5c) 0x4ed050
  virtual void DefenseSlot18(); // 24 (0x60) 0x4ec0a0

  void* operator new(unsigned int size) {
    (void)size;
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(0x94));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }
};
