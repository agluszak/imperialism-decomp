#pragma once

#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x649320
class TCountingStream : public TStream {
public:
  int positionOrByteCount;
  int maxExtentOrLimit;

  CRuntimeClass* GetRuntimeClass() override;
  TCountingStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).
};
