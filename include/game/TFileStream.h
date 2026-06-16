#pragma once

#include "game/mfc.h"
#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

class CString;

// VTABLE: IMPERIALISM 0x00649230
class TFileStream : public TStream {
public:
  // Provisional name. Points at a wrapper object whose +4 field is the
  // backing CArchive used by the serialization wrappers below.
  void* backingArchiveOrStream; // name only after grounding

  CRuntimeClass* GetRuntimeClass() const override;
  TFileStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).

  void SetBackingArchive(void* backingArchive);

  int streamSlot28() override;
  void streamSlot2c() override;
  int streamSlot30() override;
  void streamSlot34() override;
  void ReadBytes(void* buffer, int sizeBytes) override;
  void streamSlot70() override;
  void WriteBytesSlot78(void* data, int length) override;

  // 0x00489220 / 0x00489290: forward raw byte read/write to the backing
  // CArchive, asserting the backing pointer is non-null first.

  // 0x00489300 / 0x00489330: forward polymorphic object read/write to the
  // backing CArchive. The read form stores the resolved object through its
  // out-param and returns a success byte.
  char ReadObjectFromBackingArchive(void* outObject);
  void WriteObjectToBackingArchive(void* objectRef);

  // 0x00489070: serialize a length-prefixed C-string — write the length through
  // virtual slot 0x22, then the bytes through slot 0x1e.
  void WriteLengthPrefixedCString(char* text);
  void WriteCString(const CString& text);
};
