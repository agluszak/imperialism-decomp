#pragma once

#include "CObject.h"

// Mac: TStream — serialization byte stream (ReadBytes, ReadInteger, WriteObjectSize, …).
// VTABLE slots verified against IMPERIALISM.exe (e.g. minister roster 0x004d92e0 uses
// [vt+0x3c] for all bulk reads, [vt+0x40] for integer mask, [vt+0xb0] for marker byte).
class TStream : public CObject {
public:
  virtual void streamSlot14() = 0;                          // 5 (0x14)
  virtual void streamSlot18() = 0;                          // 6 (0x18)
  virtual void streamSlot1c() = 0;                          // 7 (0x1c)
  virtual void streamSlot20() = 0;                          // 8 (0x20)
  virtual void streamSlot24() = 0;                          // 9 (0x24)
  virtual void streamSlot28() = 0;                          // 10 (0x28)
  virtual void streamSlot2c() = 0;                          // 11 (0x2c)
  virtual void streamSlot30() = 0;                          // 12 (0x30)
  virtual void streamSlot34() = 0;                          // 13 (0x34)
  virtual void streamSlot38() = 0;                          // 14 (0x38)
  virtual void ReadBytes(void* buffer, int sizeBytes) = 0;  // 15 (0x3c)
  virtual int ReadInteger() = 0;                            // 16 (0x40)
  virtual void streamSlot44() = 0;                          // 17 (0x44)
  virtual void streamSlot48() = 0;                          // 18 (0x48)
  virtual short ReadShort() = 0;                            // 19 (0x4c)
  virtual void streamSlot50() = 0;                          // 20 (0x50)
  virtual void streamSlot54() = 0;                          // 21 (0x54)
  virtual void streamSlot58() = 0;                          // 22 (0x58)
  virtual void streamSlot5c() = 0;                          // 23 (0x5c)
  virtual void streamSlot60() = 0;                          // 24 (0x60)
  virtual void streamSlot64() = 0;                          // 25 (0x64)
  virtual void streamSlot68() = 0;                          // 26 (0x68)
  virtual void streamSlot6c() = 0;                          // 27 (0x6c)
  virtual void streamSlot70() = 0;                          // 28 (0x70)
  virtual void streamSlot74() = 0;                          // 29 (0x74)
  virtual void WriteBytesSlot78(void* data, int length) = 0; // 30 (0x78)
  virtual void streamSlot7c() = 0;                          // 31 (0x7c)
  virtual void streamSlot80() = 0;                          // 32 (0x80)
  virtual void streamSlot84() = 0;                          // 33 (0x84)
  virtual void WriteCountSlot88(int count) = 0;              // 34 (0x88)
  virtual void streamSlot8c() = 0;                          // 35 (0x8c)
  virtual void streamSlot90() = 0;                          // 36 (0x90)
  virtual void streamSlot94() = 0;                          // 37 (0x94)
  virtual void streamSlot98() = 0;                          // 38 (0x98)
  virtual void streamSlot9c() = 0;                          // 39 (0x9c)
  virtual void streamSlotA0() = 0;                          // 40 (0xa0)
  virtual void streamSlotA4() = 0;                          // 41 (0xa4)
  virtual void streamSlotA8() = 0;                          // 42 (0xa8)
  virtual void streamSlotAc() = 0;                          // 43 (0xac)
  virtual char ReadByte(void* outByte) = 0;                 // 44 (0xb0)
};
