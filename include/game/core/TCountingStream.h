#pragma once

#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x649320
class TCountingStream : public TStream {
public:
  // clang-format off
  virtual ~TCountingStream() override; // slot 0x01 (scalar deleting destructor)
  // slots 0x0a..0x0d: position/length accessors below
  // slot 0x1e WriteBytes owned by the hand declaration below (0x489550)
  // clang-format on
  int positionOrByteCount;
  int maxExtentOrLimit;

  DECLARE_DYNCREATE(TCountingStream)
  TCountingStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).

  int GetPosition() override;
  // NOOP: verified empty in original 0x00489490 (single ret; the packet dispatcher
  // calls it right after construction before measuring).
  void PrepareForUse();
  void SetPosition(int position) override;
  int GetLength() override;
  void SetLength(int length) override;
  // ReadBytes (slot 0x3c) is inherited unchanged from TStream.
  void WriteBytes(void* data, int length) override;
};
ASSERT_SIZE(TCountingStream, 0xc);
