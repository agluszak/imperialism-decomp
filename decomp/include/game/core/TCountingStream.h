#pragma once

#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x649320
class TCountingStream : public TStream {
public:
  // clang-format off
  // NOOP: verified empty in original 0x00489470
  virtual ~TCountingStream() override {}
  // clang-format on
  int positionOrByteCount;
  int maxExtentOrLimit;

  DECLARE_DYNCREATE(TCountingStream)
  TCountingStream();

  int GetPosition() override;
  void ICountingStream();
  void SetPosition(int position) override;
  int GetLength() override;
  void SetLength(int position) override;
  // ReadBytes (slot 0x3c) is inherited unchanged from TStream.
  void WriteBytes(const void* data, int length) override;
};
ASSERT_SIZE(TCountingStream, 0xc);
