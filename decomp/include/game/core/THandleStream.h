#pragma once

#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x649410
class THandleStream : public TStream {
public:
  // clang-format off
  // NOOP: verified empty in original 0x00489640
  virtual ~THandleStream() override {}
  virtual void Free() override;
  virtual int GrowthSize(int requestedSize);
  // clang-format on
  HGLOBAL attachedGlobalHandle;
  int streamPosition;
  int attachedSizeBytes;
  int growthSize;
  unsigned char unclassifiedByte14;

  DECLARE_DYNCREATE(THandleStream)
  THandleStream();

  void IHandleStream(HGLOBAL memoryHandle, int growthSize);

  int GetPosition() override;
  void SetPosition(int position) override;
  int GetLength() override;
  void SetLength(int length) override;
  void ReadBytes(void* buffer, int sizeBytes) override;
  void WriteBytes(const void* data, int length) override;
};
ASSERT_SIZE(THandleStream, 0x18);
