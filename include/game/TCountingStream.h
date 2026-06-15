#pragma once

#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x649320
class TCountingStream : public TStream {
public:
  int positionOrByteCount;
  int maxExtentOrLimit;

  CRuntimeClass* GetRuntimeClass() const override;
  TCountingStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).

  int streamSlot28() override;
  void streamSlot2c() override;
  int streamSlot30() override;
  void streamSlot34() override;
  void ReadBytes(void* buffer, int sizeBytes) override;
};
