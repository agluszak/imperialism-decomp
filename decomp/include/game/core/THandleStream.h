#pragma once

#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x649410
class THandleStream : public TStream {
public:
  // clang-format off
  // NOOP: verified empty in original 0x00489640
  virtual ~THandleStream() override {} // slot 0x01 (scalar deleting destructor)
  virtual void Free() override; // slot 0x07 0x4896a0
  virtual int GrowthSize(int requestedSize); // slot 0x31 0x489720
  // clang-format on
  // Field semantics evidenced by AttachGlobalMemoryHandleAndResetPosition (0x489660):
  // +0x04 receives the HGLOBAL, +0x08 is zeroed (position), +0x0c receives
  // GlobalSize(handle), +0x10 receives the caller's mode word (ctor default 1).
  HGLOBAL attachedGlobalHandle; // +0x04
  int streamPosition;           // +0x08
  int attachedSizeBytes;        // +0x0c
  int growthSize10;             // +0x10
  unsigned char unclassifiedByte14;

  DECLARE_DYNCREATE(THandleStream)
  THandleStream();

  void AttachGlobalMemoryHandleAndResetPosition(HGLOBAL memoryHandle, int growthSize);

  int GetPosition() override;
  void SetPosition(int position) override;
  int GetLength() override;
  void SetLength(int length) override;
  void ReadBytes(void* buffer, int sizeBytes) override;
  void WriteBytes(const void* data, int length) override;
};
ASSERT_SIZE(THandleStream, 0x18);
