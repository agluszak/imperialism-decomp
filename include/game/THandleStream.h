#pragma once

#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x649410
class THandleStream : public TStream {
public:
  // Behavior-derived: 0x00489550 advances currentExtent by a delta and tracks
  // highWatermark as its running maximum. Field names remain provisional.
  int currentExtent;
  int highWatermark;
  int handleOrBuffer;
  int position;
  bool ownsHandleOrDirty;

  CRuntimeClass* GetRuntimeClass() const override;
  THandleStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).

  // 0x00489550: advance currentExtent by delta, raising highWatermark to match.
  void AdvanceExtent(int handle, int delta);

  void streamSlot1c() override;
  int streamSlot28() override;
  void streamSlot2c() override;
  int streamSlot30() override;
  void streamSlot34() override;
  void ReadBytes(void* buffer, int sizeBytes) override;
  void WriteBytesSlot78(void* data, int length) override;
};
