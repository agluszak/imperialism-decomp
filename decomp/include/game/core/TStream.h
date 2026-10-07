#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/mfc.h"

class CString;

struct VPoint {
  int vertical;
  int horizontal;
};
ASSERT_SIZE(VPoint, 0x8);

// VTABLE: IMPERIALISM 0x00649140
class TStream : public TObject {
public:
  DECLARE_DYNCREATE(TStream)
  TStream() {}

public:
  // FUNCTION: IMPERIALISM 0x00488a40
  virtual ~TStream() override {}
  void Free() override;
  virtual int GetPosition();
  virtual void SetPosition(int position);
  virtual int GetLength();
  virtual void SetLength(int length);
  virtual bool AtEnd();
  virtual void ReadBytes(void* buffer, int sizeBytes); // 15 (0x3c) primitive, no-op base
  virtual char ReadByte();
  virtual char ReadBoolean();
  virtual void ReadCharacter(short* outCharacter); // 18 (0x48) 1 byte into a short
  virtual short ReadInteger();                     // 19 (0x4c) 2 bytes (MacApp Integer)
  virtual int ReadLong();
  virtual void ReadVPoint(VPoint* outPoint); // 21 (0x54) 8 bytes, two longs
  virtual void ReadRect(void* out);
  virtual void ReadVRect(void* out);
  virtual void ReadUnclassified16ByteRecord(void* out);
  virtual void ReadPoint(void* out);
  virtual int ReadIDType();
  virtual void ReadString(void* buffer, int maxLen);        // 27 (0x6c) 2-byte length + bytes
  virtual void ReadSharedString(CString* dest, int maxLen); // 28 (0x70) same, into a CString
  virtual void ReadWordAlign();                             // 29 (0x74) skip to an even offset
  virtual void WriteBytes(const void* data, int length);    // 30 (0x78) primitive, no-op base
  virtual void WriteByte(unsigned char value);
  virtual void WriteBoolean(unsigned char value);
  virtual void WriteCharacter(short value); // 33 (0x84) 1 byte (the high one)
  virtual void WriteInteger(short value);   // 34 (0x88) 2 bytes (MacApp Integer)
  virtual void WriteLong(int value);
  virtual void WriteVPoint(double value);
  virtual void WriteRect(void* data);
  virtual void WriteVRect(void* data);
  virtual void WriteUnclassified16ByteRecord(void* data); // 39 (0x9c) 16 bytes, mirrors 0x60
  virtual void WritePoint(void* data);
  virtual void WriteIDType(int value);
  virtual void WriteString(char* text);                  // 42 (0xa8) 2-byte length + bytes
  virtual void WriteSharedString(CString* sharedString); // 43 (0xac) same, from a CString
  virtual bool ReadObject(void* outObject);              // 44 (0xb0) polymorphic CObject read
  virtual void WriteObject(void* object, int flag);      // 45 (0xb4) polymorphic CObject write
  virtual void WriteWordAlign();                         // 46 (0xb8) pad to an even offset
  virtual int AssertMcAppStreamLine304(int unusedArg);
  virtual void AssertMcAppStreamLine596(int unusedArg1, int unusedArg2);
};
ASSERT_SIZE(TStream, 0x4);
