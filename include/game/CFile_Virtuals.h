#pragma once

#include "decomp_types.h"

class CFile_Virtuals {
public:
  virtual void dummy00() = 0;
  virtual void dummy04() = 0;
  virtual void dummy08() = 0;
  virtual void dummy0C() = 0;
  virtual void dummy10() = 0;
  virtual void dummy14() = 0;
  virtual void dummy18() = 0;
  virtual void dummy1C() = 0;
  virtual void dummy20() = 0;
  virtual void dummy24() = 0;
  virtual void dummy28() = 0;
  virtual void dummy2C() = 0;
  virtual void SeekSlot30(int arg1, int arg2) = 0; // 0x30
  virtual void dummy34() = 0;
  virtual void dummy38() = 0;
  virtual int ReadBytesSlot3C(void* buffer, int count) = 0;   // 0x3C
  virtual void WriteBytesSlot40(void* buffer, int count) = 0; // 0x40
  virtual void dummy44() = 0;
  virtual void dummy48() = 0;
  virtual void dummy4C() = 0;
  virtual void dummy50() = 0;
  virtual void dummy54() = 0;
  virtual void GetBufferPtrSlot58(int arg1, int arg2, void* arg3, void* arg4) = 0; // 0x58
};
