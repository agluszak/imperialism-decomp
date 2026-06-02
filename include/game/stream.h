#pragma once

#include "CObject.h"
#include "compat.h"
#include "decomp_types.h"

// MFC-style serialization stream hierarchy (TStream family). Each concrete
// stream installs its own vtable and is reset to the shared CObject runtime
// vtable on teardown.

class TStream : public CObject {
public:
  // virtual stream API slots, initially with conservative names.
};

// VTABLE: IMPERIALISM 0x00649230
class TFileStream : public TStream {
public:
  void* backingArchiveOrStream;  // name only after grounding

  void* GetRuntimeClass() override;
  TFileStream();
  void* DestructTFileStreamAndMaybeFree(unsigned int flags);
};

// VTABLE: IMPERIALISM 0x649320
class TCountingStream : public TStream {
public:
  int positionOrByteCount;
  int maxExtentOrLimit;

  void* GetRuntimeClass() override;
  TCountingStream();
  void DestructTCountingStreamBaseState();
  void* DestructTCountingStreamAndMaybeFree(byte freeSelfFlag);
};

// VTABLE: IMPERIALISM 0x649410
class THandleStream : public TStream {
public:
  int directionOrMode;
  int highWatermark;
  int handleOrBuffer;
  int position;
  bool ownsHandleOrDirty;

  void* GetRuntimeClass() override;
  THandleStream();
  void DestructTHandleStreamBaseState();
  void* DestructTHandleStreamAndMaybeFree(byte freeSelfFlag);
};
