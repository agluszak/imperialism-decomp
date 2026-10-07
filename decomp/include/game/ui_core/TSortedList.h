#pragma once

#include "compat.h"
#include "game/app/TObject.h"
#include "game/mfc.h"

class TStream;

typedef short(__cdecl* TSortedListCompareFunc)(void* a, void* b, void* context);

// VTABLE: IMPERIALISM 0x00648ee0
class TSortedList : public TObject {
public:
  // FUNCTION: IMPERIALISM 0x00488920
  ~TSortedList() override {}
  DECLARE_DYNCREATE(TSortedList)

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  int GetIdentityItemNo(void* item);

  virtual POSITION AddHead(void* item);
  virtual POSITION AddHeadEx(void* item, int unused1 = 0, int unused2 = 0);
  virtual POSITION AddTail(void* item);
  virtual POSITION AddTailEx(void* item, int unused1 = 0, int unused2 = 0);
  virtual POSITION Push(void* item = 0);
  virtual void* Pop(); // MacApp TList::Pop -- removes the tail
  virtual POSITION Queue(void* item = 0);
  virtual void* Dequeue(); // MacApp TList::Dequeue -- removes the head
  virtual int GetCount();
  virtual void* GetEntryByOrdinal(int ordinal = 0);
  virtual void RemoveAtOrdinal(int ordinal);
  virtual void FreePayloads();
  virtual void FreeList();
  virtual void RemoveAll();
  virtual void SetAtOrdinal(int ordinal, void** entryPtr, int unusedFlag);
  virtual void Sort();
  virtual void SortBy(TSortedListCompareFunc compare, void* context);
  virtual short Compare(void* a, void* b);
  virtual void QuickSort(int lo, int hi, TSortedListCompareFunc compare, void* context);
  // Hoare partition core over ordinals [lo, hi]; pivot = payload at ordinal lo.
  virtual int QSPartitionCore(int lo, int hi, TSortedListCompareFunc compare, void* context);
  // ORACLE: Mac QSPartition: swaps a random ordinal into the pivot position, then runs the core.
  virtual int QSPartition(int lo, int hi, TSortedListCompareFunc compare, void* context);

  CPtrList listState;

  // FUNCTION: IMPERIALISM 0x004a8640
  TSortedList() : listState(10) {}
};

ASSERT_SIZE(TSortedList, 0x20);
