#pragma once

#include "game/mfc.h"

#include <afxtempl.h>

class TStream;

// VTABLE: IMPERIALISM 0x00650a08
class TLongintList : public CList<long, long> {
public:
  // NOOP: verified empty in original 0x004d6a5d
  TLongintList() {}

  void Dump(CDumpContext& dc) const override; // slot 0x10 0x4c6b60

  virtual void InsertLast(long value);                                     // slot 0x14 0x4c6740
  virtual void InsertLastEx(long value, int unused1 = 0, int unused2 = 0); // slot 0x18 0x4c67e0
  virtual void NoOpWriteTo(TStream* stream);                               // slot 0x1c 0x487f70
  virtual void NoOpReadFrom(TStream* stream);                              // slot 0x20 0x487f90
  virtual long At(long oneBasedIndex);                                     // slot 0x24 0x4c6880
  virtual int GetSize();                                                   // slot 0x28 0x4c68c0
  virtual void AtDelete(long oneBasedIndex);                               // slot 0x2c 0x4c68e0
  virtual void RemoveAll();                                                // slot 0x30 0x4c69a0
  virtual void Delete(long value);                                         // slot 0x34 0x4c69e0
  virtual void Free();                                                     // slot 0x38 0x4c6bf0
};

ASSERT_SIZE(TLongintList, 0x1c);

class CLongintIterator {
public:
  CLongintIterator(TLongintList* list) : ownerList(list) {}

  long FirstLong();
  int More();
  long NextLong();

  POSITION nextPosition;   // +0x00
  TLongintList* ownerList; // +0x04
  long current;            // +0x08
};

ASSERT_SIZE(CLongintIterator, 0x0c);
