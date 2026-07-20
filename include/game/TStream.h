#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

class CString;

// Mac: TStream — serialization byte stream (ReadBytes, ReadInteger, WriteObjectSize, …).
// VTABLE slots verified against IMPERIALISM.exe (e.g. minister roster 0x004d92e0 uses
// [vt+0x3c] for all bulk reads, [vt+0x40] for integer mask, [vt+0xb0] for marker byte).
//
// TStream is a CONCRETE base: it provides default implementations for the typed
// read/write accessors (slots 0x40..0xa4), each delegating to the two primitives
// ReadBytes (slot 0x3c) and WriteBytesSlot78 (slot 0x78) which concrete subclasses
// (TFileStream, THandleStream, TCountingStream) override. TStream's own primitive
// bodies are genuine no-ops (the base class is never streamed through directly) --
// all slots below are ported and 100%-matched.
//
// VTABLE: IMPERIALISM 0x00649140
class TStream : public TObject {
public:
  DECLARE_DYNCREATE(TStream)
  TStream();

public:
  virtual ~TStream() override;
  // Slots 0x14/0x18 (WriteTo/ReadFrom) and 0x20/0x24 (ShallowClone/ShallowFree)
  // are inherited from TObject unchanged; 0x1c (Free) is overridden below.
  void Free() override;           // 7 (0x1c)  0x00488ab0
  virtual int streamSlot28();     // 10 (0x28) 0x00488ad0 (read by streamSlot38)
  virtual void streamSlot2c(int); // 11 (0x2c) 0x00488e30
  virtual int streamSlot30();     // 12 (0x30) 0x00488af0 (read by streamSlot38)
  virtual void streamSlot34(int); // 13 (0x34) 0x00488e50
  virtual char streamSlot38();    // 14 (0x38) 0x00488a80
  virtual void ReadBytes(void* buffer,
                         int sizeBytes); // 15 (0x3c) primitive 0x00488b40 (no-op base)
  virtual char ReadInteger();            // 16 (0x40) 0x00488b60 read 1 byte
  virtual char streamSlot44();           // 17 (0x44) 0x00488b90 read 1 byte
  virtual void streamSlot48(void* out);  // 18 (0x48) 0x00488bc0
  virtual short ReadShort();             // 19 (0x4c) 0x00488bf0
  virtual int streamSlot50();            // 20 (0x50) 0x00488c20
  virtual void streamSlot54(void* out);  // 21 (0x54) 0x00488ce0
  virtual void streamSlot58(void* out);  // 22 (0x58) 0x00488d20
  virtual void streamSlot5c(void* out);  // 23 (0x5c) 0x00488d40
  virtual void streamSlot60(void* out);  // 24 (0x60) 0x00488d60
  virtual void streamSlot64(void* out);  // 25 (0x64) 0x00488d80
  virtual int streamSlot68();            // 26 (0x68) 0x00488da0
  virtual void streamSlot6c(void* buffer, int maxLen);  // 27 (0x6c) 0x00488ca0 read len+bytes
  virtual void streamSlot70(CString* dest, int maxLen); // 28 (0x70) 0x00488c50 read shared string
  virtual void streamSlot74();                          // 29 (0x74) 0x00488dd0
  virtual void WriteBytesSlot78(void* data,
                                int length);      // 30 (0x78) primitive 0x00488e70 (no-op base)
  virtual void streamSlot7c(unsigned char value); // 31 (0x7c) 0x00488e90
  virtual void streamSlot80(unsigned char value); // 32 (0x80) 0x00488eb0
  virtual void streamSlot84(short value);         // 33 (0x84) 0x00488ed0 write high byte
  virtual void WriteCountSlot88(int count);       // 34 (0x88) 0x00488ef0
  virtual void streamSlot8c(int value);           // 35 (0x8c) 0x00488f10
  virtual void streamSlot90(double value);        // 36 (0x90) 0x00488f30
  virtual void streamSlot94(void* data);          // 37 (0x94) 0x00488f50
  virtual void streamSlot98(void* data);          // 38 (0x98) 0x00488f70
  virtual void streamSlot9c(void* data);          // 39 (0x9c) 0x00488f90
  virtual void streamSlotA0(void* data);          // 40 (0xa0) 0x00488fb0
  virtual void streamSlotA4(int value);           // 41 (0xa4) 0x00488fd0
  virtual void WriteLengthPrefixedCString(char* text);    // 42 (0xa8) writes a C string
  virtual void streamSlotAc(CString* sharedString);       // 43 (0xac) writes a CString ref
  virtual char ReadByte(void* outByte);                   // 44 (0xb0) primitive 0x00489980
  virtual void WriteObjectSlotB4(void* object, int flag); // 45 (0xb4) writes a polymorphic object
  virtual void OrphanCallChain_C2_I18_00488ff0();         // 46 (0xb8)
  virtual void AssertMcAppStreamLine304(int unusedArg);   // 47 (0xbc)
  virtual void AssertMcAppStreamLine596(int unusedArg1, int unusedArg2); // 48 (0xc0)
};
