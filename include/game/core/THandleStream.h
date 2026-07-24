#pragma once

#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x649410
class THandleStream : public TStream {
public:
  // clang-format off
  virtual ~THandleStream() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override; // slot 0x07 0x4896a0
  // slots 0x0a..0x0d: position/length accessors below
  // slot 0x1e WriteBytesSlot78 owned by the hand declaration below (0x489810)
  virtual int GrowthSize(int requestedSize); // slot 0x31 0x489720
  // clang-format on
  // Field semantics evidenced by AttachGlobalMemoryHandleAndResetPosition (0x489660):
  // +0x04 receives the HGLOBAL, +0x08 is zeroed (position), +0x0c receives
  // GlobalSize(handle), +0x10 receives the caller's mode word (ctor default 1).
  HGLOBAL attachedGlobalHandle; // +0x04
  int streamPosition;           // +0x08
  int attachedSizeBytes;        // +0x0c
  int growthSize10;             // +0x10
  // +0x14 -- one byte, zeroed by the constructor (0x004895e0 stores CL) and never read
  // or written anywhere else in the retail image. The previous name asserted an
  // ownership-or-dirty meaning that no writer, reader, or Mac signature supports, so
  // the slot stays opaque and explicitly unclassified.
  // UNRESOLVED_FIELD_ATTRIBUTION: no observed reader; candidate readings (handle
  // ownership flag, dirty flag) are both unevidenced.
  unsigned char unclassifiedByte14;

  DECLARE_DYNCREATE(THandleStream)
  THandleStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).

  // Attach a global-memory handle: mode from the caller, position reset to 0,
  // size from GlobalSize. A null handle only resets position/mode. (0x489660)
  void AttachGlobalMemoryHandleAndResetPosition(HGLOBAL memoryHandle, int growthSize);

  int GetPosition() override;
  void SetPosition(int position) override;
  int GetLength() override;
  void SetLength(int length) override;
  void ReadBytes(void* buffer, int sizeBytes) override;
  void WriteBytesSlot78(void* data, int length) override;
};
ASSERT_SIZE(THandleStream, 0x18);
