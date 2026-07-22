#pragma once

#include "game/mfc.h"
#include "TStream.h"
#include "game/ArchiveStreamAdapter.h"
#include "compat.h"
#include "decomp_types.h"

class CString;

// VTABLE: IMPERIALISM 0x00649230
class TFileStream : public TStream {
public:
  // clang-format off
  virtual ~TFileStream() override; // slot 0x01 (scalar deleting destructor)
  // slots 0x0a..0x0d: position/length accessors below
  // slot 0x1c streamSlot70 owned by the hand declaration below (0x489360)
  // slot 0x1e WriteBytesSlot78 owned by the hand declaration below (0x489290)
  virtual void streamSlotAc(CString* sharedString) override;       // slot 0x2b 0x489390
  virtual char ReadByte(void* outByte) override;                   // slot 0x2c 0x489300
  virtual void WriteObjectSlotB4(void* object, int flag) override; // slot 0x2d 0x489330
  // clang-format on
  ArchiveStreamAdapter* backingArchiveOrStream;

  DECLARE_DYNCREATE(TFileStream)
  TFileStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).

  void SetBackingArchive(ArchiveStreamAdapter* backingArchive);

  int GetPosition() override;
  void SetPosition(int position) override;
  int GetLength() override;
  void SetLength(int length) override;
  void ReadBytes(void* buffer, int sizeBytes) override;
  void streamSlot70(CString* dest, int maxLen) override;
  void WriteBytesSlot78(void* data, int length) override;

  // 0x00489220 / 0x00489290: forward raw byte read/write to the backing
  // CArchive, asserting the backing pointer is non-null first.

  // 0x00489300 / 0x00489330: forward polymorphic object read/write to the
  // backing CArchive. The read form stores the resolved object through its
  // out-param and returns a success byte.
};
