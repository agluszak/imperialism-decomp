#pragma once

#include "game/TMinister.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// AI interior minister branch.
// VTABLE: IMPERIALISM 0x00650808
class TInteriorMinister : public TMinister {
public:
  TInteriorMinister();

  CRuntimeClass* GetRuntimeClass() const override;
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void MinisterSlot0A() override;
  void NotifySlot44(void* receiver) override;
  virtual void MinisterSlot12();
  virtual void Call4C();
  virtual void MinisterSlot14();
  virtual void Call54();
};
