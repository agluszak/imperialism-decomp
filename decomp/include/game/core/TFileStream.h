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
  virtual void WriteSharedString(CString* sharedString) override;       // slot 0x2b 0x489390
  virtual bool ReadObject(void* outByte) override;                   // slot 0x2c 0x489300
  virtual void WriteObject(void* object, int flag) override; // slot 0x2d 0x489330
  // clang-format on
  ArchiveStreamAdapter* backingArchiveOrStream;

  DECLARE_DYNCREATE(TFileStream)
  TFileStream();

  void IFileStream(ArchiveStreamAdapter* backingArchive);

  int GetPosition() override;
  void SetPosition(int position) override;
  int GetLength() override;
  void SetLength(int length) override;
  void ReadBytes(void* buffer, int sizeBytes) override;
  void ReadSharedString(CString* dest, int maxLen) override;
  void WriteBytes(const void* data, int length) override;
};
ASSERT_SIZE(TFileStream, 0x8);
