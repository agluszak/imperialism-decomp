#pragma once

#include "game/mfc.h"

#include <afxtempl.h>

class TStream;

// VTABLE: IMPERIALISM 0x00650a08
class TLongintList : public CList<long, long> {
public:
  // NOOP: verified empty in original 0x004d6a5d
  TLongintList() {}

  void Dump(CDumpContext& dc) const override;

  virtual void InsertLast(long value);
  virtual void InsertLastEx(long value, int unused1 = 0, int unused2 = 0);
  virtual void NoOpWriteTo(TStream* stream);
  virtual void NoOpReadFrom(TStream* stream);
  virtual long At(long oneBasedIndex);
  virtual int GetSize();
  virtual void AtDelete(long oneBasedIndex);
  virtual void RemoveAll();
  virtual void Delete(long value);
  virtual void Free();
};

ASSERT_SIZE(TLongintList, 0x1c);

class CLongintIterator {
public:
  CLongintIterator(TLongintList* list) : ownerList(list) {}

  long FirstLong();
  int More();
  long NextLong();

  POSITION nextPosition;
  TLongintList* ownerList;
  long current;
};

ASSERT_SIZE(CLongintIterator, 0x0c);
