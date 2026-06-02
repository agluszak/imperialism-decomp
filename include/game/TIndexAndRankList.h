#pragma once

#include "decomp_types.h"

class TIndexAndRankList {
 public:
  virtual void slot00() {}
  virtual void slot04() {}
  virtual void slot08() {}
  virtual void slot0c() {}
  virtual void slot10() {}
  virtual void slot14() {}
  virtual void slot18() {}
  virtual void ResetPtrListRecordsSlot1C() {}
  virtual void slot20() {}
  virtual void slot24() {}
  virtual void ShrinkCapacitySlot28() {}

  void** entries;
  int count;
  int capacity;
  int growBy;

  TIndexAndRankList* CPtrArray();
  void* DestructCObArrayAndMaybeFree(byte freeSelfFlag);

  void SetSize(int nNewSize, int nGrowBy);
  void SetAtGrow(int nIndex, void* newElement);
  void InsertAt(int nIndex, void* newElement, int nCount);
  void RemoveAt(int nIndex, int nCount);
};

typedef char TIndexAndRankListSizeMustMatch[(sizeof(TIndexAndRankList) == 0x14) ? 1 : -1];
