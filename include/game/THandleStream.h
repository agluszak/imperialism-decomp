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

  void* GetRuntimeClass() override;
  THandleStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).

  // 0x00489550: advance currentExtent by delta, raising highWatermark to match.
  void AdvanceExtent(int handle, int delta);
};
