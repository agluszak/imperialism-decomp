#pragma once

#include "game/TMinister.h"

// VTABLE: IMPERIALISM 0x006549b0
class TDefenseMinister : public TMinister {
public:
  TDefenseMinister();
  void InitializeBaseOrderArrayMetrics();

  CRuntimeClass* GetRuntimeClass() const override; // slot 0 (0x4ec0c0)
  void WriteTo(TStream* stream) override;          // 5 (0x4ec1d0)
  void ReadFrom(TStream* stream) override;         // 6 (0x4ec2f0)
  void MinisterSlot0A() override; // 10 (0x4ec3d0)
  virtual void MinisterSlot12();    // 18 (0x4ec450)
  virtual void Call4C();            // 19 (0x4ec4c0)
  virtual void MinisterSlot14();    // 20 (0x4ec540)
  virtual void Call54();            // 21 (0x4ecbb0)

  // TDefenseMinister-introduced extension (vtable 0x6549b0 slots 22-24, byte 0x58-0x60).
  // Slots 25-29 are NULL/abstract trailing slots in orig (reccmp drops them); not declared.
  // TNapoleonMinister's vtable begins at 0x654a28 (slot 30).
  virtual void DefenseSlot16(); // 22 (0x58) 0x4ecf20
  virtual void DefenseSlot17(); // 23 (0x5c) 0x4ed050
  virtual void DefenseSlot18(); // 24 (0x60) 0x4ec0a0
};
