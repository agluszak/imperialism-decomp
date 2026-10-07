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
  virtual ~TFileStream() override;
  virtual void WriteSharedString(CString* sharedString) override;
  virtual bool ReadObject(void* outObject) override;
  virtual void WriteObject(void* object, int flag) override;
  // clang-format on
  ArchiveStreamAdapter* backingArchiveOrStream;

  DECLARE_DYNCREATE(TFileStream)
  TFileStream();

  void IFileStream(ArchiveStreamAdapter* backingArchive);

  int GetPosition() override;
  void SetPosition(int position) override;
  int GetLength() override;
  void SetLength(int length) override;
  void ReadBytes(void* destination, int requestedCount) override;
  void ReadSharedString(CString* dest, int maxLen) override;
  void WriteBytes(const void* source, int byteCount) override;
};
ASSERT_SIZE(TFileStream, 0x8);
