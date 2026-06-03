#pragma once

#include "CArchive.h"
#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x00649230
class TFileStream : public TStream {
 public:
  // Provisional name. Points at a wrapper object whose +4 field is the
  // backing CArchive used by the serialization wrappers below.
  void* backingArchiveOrStream;  // name only after grounding

  void* GetRuntimeClass() override;
  TFileStream();
  void* DestructTFileStreamAndMaybeFree(unsigned int flags);

  // 0x00489220 / 0x00489290: forward raw byte read/write to the backing
  // CArchive, asserting the backing pointer is non-null first.
  int ReadBytesFromBackingArchive(void* destination, unsigned int requestedCount);
  void WriteBytesToBackingArchive(const void* source, unsigned int byteCount);

  // 0x00489300 / 0x00489330: forward polymorphic object read/write to the
  // backing CArchive. The read form stores the resolved object through its
  // out-param and returns a success byte.
  char ReadObjectFromBackingArchive(void* outObject);
  void WriteObjectToBackingArchive(void* objectRef);

  // 0x00489070: serialize a length-prefixed C-string — write the length through
  // virtual slot 0x22, then the bytes through slot 0x1e.
  void WriteLengthPrefixedCString(char* text);
};
