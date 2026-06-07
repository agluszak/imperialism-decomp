#pragma once

#include "CObject.h"

// MFC-style serialization stream hierarchy base (TStream family). Each concrete
// stream installs its own vtable and is reset to the shared CObject runtime
// vtable on teardown.
class TStream : public CObject {
public:
  virtual void dummy_slot_14() = 0;                          // 5 (0x14)
  virtual void dummy_slot_18() = 0;                          // 6 (0x18)
  virtual void dummy_slot_1c() = 0;                          // 7 (0x1c)
  virtual void dummy_slot_20() = 0;                          // 8 (0x20)
  virtual void dummy_slot_24() = 0;                          // 9 (0x24)
  virtual void dummy_slot_28() = 0;                          // 10 (0x28)
  virtual void dummy_slot_2c() = 0;                          // 11 (0x2c)
  virtual void dummy_slot_30() = 0;                          // 12 (0x30)
  virtual void dummy_slot_34() = 0;                          // 13 (0x34)
  virtual void dummy_slot_38() = 0;                          // 14 (0x38)
  virtual void dummy_slot_3c() = 0;                          // 15 (0x3c)
  virtual void dummy_slot_40() = 0;                          // 16 (0x40)
  virtual void dummy_slot_44() = 0;                          // 17 (0x44)
  virtual void dummy_slot_48() = 0;                          // 18 (0x48)
  virtual void dummy_slot_4c() = 0;                          // 19 (0x4c)
  virtual void dummy_slot_50() = 0;                          // 20 (0x50)
  virtual void dummy_slot_54() = 0;                          // 21 (0x54)
  virtual void dummy_slot_58() = 0;                          // 22 (0x58)
  virtual void dummy_slot_5c() = 0;                          // 23 (0x5c)
  virtual void dummy_slot_60() = 0;                          // 24 (0x60)
  virtual void dummy_slot_64() = 0;                          // 25 (0x64)
  virtual void dummy_slot_68() = 0;                          // 26 (0x68)
  virtual void dummy_slot_6c() = 0;                          // 27 (0x6c)
  virtual void dummy_slot_70() = 0;                          // 28 (0x70)
  virtual void dummy_slot_74() = 0;                          // 29 (0x74)
  virtual void WriteBytesSlot78(void* data, int length) = 0; // 30 (0x78)
  virtual void dummy_slot_7c() = 0;                          // 31 (0x7c)
  virtual void dummy_slot_80() = 0;                          // 32 (0x80)
  virtual void dummy_slot_84() = 0;                          // 33 (0x84)
  virtual void WriteCountSlot88(int count) = 0;              // 34 (0x88)
};
