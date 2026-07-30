#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/mfc.h"

class CString;

// MacApp VPoint: two 32-bit coordinates. The Windows stream slots read/write the
// complete eight-byte value even though the native Windows POINT uses 16-bit fields
// in this VC5-era codebase.
struct VPoint {
  int vertical;
  int horizontal;
};
ASSERT_SIZE(VPoint, 0x8);

// TStream -- the MacApp-derived serialization byte stream the save format is built on.
// Names come from the Mac CodeWarrior oracle (name oracle only, per AGENTS.md Hard Rule
// 12); every width below is proven by the corresponding body in TStream.cpp, all of
// which are ported and 100%-matched.
//
// WATCH THE WIDTHS. These are MacApp names, and MacApp's scalar sizes are not the C++
// ones a reader expects:
//
//     ReadByte / WriteByte          1 byte    (slot 0x40 / 0x7c)
//     ReadBoolean / WriteBoolean    1 byte    (slot 0x44 / 0x80)
//     ReadCharacter / WriteCharacter 1 byte, widened to/narrowed from a short
//     ReadInteger / WriteInteger    *** 2 bytes *** -- MacApp Integer is 16-bit
//     ReadLong / WriteLong          4 bytes
//
// Picking the wrong one silently shifts every following field, and because the save
// stream is unframed there is no way to recover. This has already cost one real bug:
// TNavyMission::ReadFrom read its zone ids through the 1-byte slot where the original
// used the 2-byte one, losing 2 bytes per navy mission. `just serde-audit` exists to
// catch that class of defect -- run it after touching any serializer.
//
// The read slots (0x40..0x70) and write slots (0x7c..0xac) mirror each other exactly,
// pair for pair, which is how the mapping above was recovered.
//
// TStream is a CONCRETE base: it provides default implementations for every typed
// accessor, each delegating to the two primitives ReadBytes (slot 0x3c) and WriteBytes
// (slot 0x78) that concrete subclasses (TFileStream, THandleStream, TCountingStream)
// override. TStream's own primitive bodies are genuine no-ops -- the base class is never
// streamed through directly.
//
// VTABLE: IMPERIALISM 0x00649140
class TStream : public TObject {
public:
  DECLARE_DYNCREATE(TStream)
  // In-class inline: the original has no out-of-line TStream::TStream -- every
  // caller absorbs it, so an out-of-line definition pessimizes them into a call.
  // NOOP: verified empty in original 0x004889a1 (no standalone TStream::TStream body exists: construction is fully inlined into CreateObject 0x004889a0; that address is its operator-new call site)
  TStream() {}

public:
  // FUNCTION: IMPERIALISM 0x00488a40
  virtual ~TStream() override {}
  // Slots 0x14/0x18 (WriteTo/ReadFrom) and 0x20/0x24 (ShallowClone/ShallowFree)
  // are inherited from TObject unchanged; 0x1c (Free) is overridden below.
  void Free() override;                                // 7 (0x1c)  0x00488ab0
  virtual int GetPosition();                           // 10 (0x28) 0x00488ad0
  virtual void SetPosition(int position);              // 11 (0x2c) 0x00488e30
  virtual int GetLength();                             // 12 (0x30) 0x00488af0
  virtual void SetLength(int length);                  // 13 (0x34) 0x00488e50
  virtual char IsAtEnd();                              // 14 (0x38) 0x00488a80
  virtual void ReadBytes(void* buffer, int sizeBytes); // 15 (0x3c) primitive, no-op base
  virtual char ReadByte();                             // 16 (0x40) 1 byte
  virtual char ReadBoolean();                          // 17 (0x44) 1 byte
  virtual void ReadCharacter(short* outCharacter);     // 18 (0x48) 1 byte into a short
  virtual short ReadInteger();                         // 19 (0x4c) 2 bytes (MacApp Integer)
  virtual int ReadLong();                              // 20 (0x50) 4 bytes
  virtual void ReadVPoint(VPoint* outPoint);           // 21 (0x54) 8 bytes, two longs
  virtual void ReadRect(void* out);                    // 22 (0x58) 8 bytes
  virtual void ReadVRect(void* out);                   // 23 (0x5c) 16 bytes
  // 0x60 has no call site anywhere in the image and no Mac counterpart of this width,
  // so it keeps a descriptive placeholder rather than a guessed identity.
  virtual void ReadUnclassified16ByteRecord(void* out);     // 24 (0x60) 16 bytes
  virtual void ReadPoint(void* out);                        // 25 (0x64) 4 bytes
  virtual int ReadIDType();                                 // 26 (0x68) 4 bytes
  virtual void ReadString(void* buffer, int maxLen);        // 27 (0x6c) 2-byte length + bytes
  virtual void ReadSharedString(CString* dest, int maxLen); // 28 (0x70) same, into a CString
  virtual void ReadWordAlign();                             // 29 (0x74) skip to an even offset
  virtual void WriteBytes(const void* data, int length);    // 30 (0x78) primitive, no-op base
  virtual void WriteByte(unsigned char value);              // 31 (0x7c) 1 byte
  virtual void WriteBoolean(unsigned char value);           // 32 (0x80) 1 byte
  virtual void WriteCharacter(short value);                 // 33 (0x84) 1 byte (the high one)
  virtual void WriteInteger(short value);                   // 34 (0x88) 2 bytes (MacApp Integer)
  virtual void WriteLong(int value);                        // 35 (0x8c) 4 bytes
  virtual void WriteVPoint(double value);                   // 36 (0x90) 8 bytes
  virtual void WriteRect(void* data);                       // 37 (0x94) 8 bytes
  virtual void WriteVRect(void* data);                      // 38 (0x98) 16 bytes
  virtual void WriteUnclassified16ByteRecord(void* data);   // 39 (0x9c) 16 bytes, mirrors 0x60
  virtual void WritePoint(void* data);                      // 40 (0xa0) 4 bytes
  virtual void WriteIDType(int value);                      // 41 (0xa4) 4 bytes
  virtual void WriteString(char* text);                     // 42 (0xa8) 2-byte length + bytes
  virtual void WriteSharedString(CString* sharedString);    // 43 (0xac) same, from a CString
  virtual char ReadObject(void* outObject);                 // 44 (0xb0) polymorphic CObject read
  virtual void WriteObject(void* object, int flag);         // 45 (0xb4) polymorphic CObject write
  virtual void WriteWordAlign();                            // 46 (0xb8) pad to an even offset
  virtual int AssertMcAppStreamLine304(int unusedArg);      // 47 (0xbc)
  virtual void AssertMcAppStreamLine596(int unusedArg1, int unusedArg2); // 48 (0xc0)
};
ASSERT_SIZE(TStream, 0x4);
