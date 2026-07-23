#pragma once

#include "compat.h"
#include "game/app/TObject.h"
#include "game/mfc.h"

class TStream;

// Three-way comparator shape used by the MacApp-heritage sort API below: short verdict
// (<0 / 0 / >0) in AX, __cdecl, with the caller-supplied context as the third argument
// (Sort() passes the list itself so the default trampoline can dispatch the virtual
// Compare).
typedef short(__cdecl* TSortedListCompareFunc)(void* a, void* b, void* context);

// TObject-derived linked-list base (vtable 0x00648ee0).
// Base recovered from CRuntimeClass descriptor: TSortedList -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00648ee0
class TSortedList : public TObject {
public:
  // FUNCTION: IMPERIALISM 0x00488920
  ~TSortedList() override {}
  DECLARE_DYNCREATE(TSortedList)

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  int FindOneBasedOrdinalOf(void* item);

  // AddHead/AddTail are MacApp TList::InsertFirst/InsertLast. The 0x2c and 0x34 slots
  // have the same bodies but RET 0xc (three stack dwords) instead of RET 0x4; only the
  // first is read. Nothing in the recovered tree calls them, so which MacApp entry point
  // they are (the three-argument TDynArray insert family is the obvious candidate) stays
  // unproven -- "Ex" marks the extra-argument sibling until a caller settles it.
  virtual POSITION AddHead(void* item);
  virtual POSITION AddHeadEx(void* item, int unused1 = 0, int unused2 = 0);
  virtual POSITION AddTail(void* item);
  virtual POSITION AddTailEx(void* item, int unused1 = 0, int unused2 = 0);
  // Slots 0x38..0x44 are MacApp TList's two stack/queue pairs over the same storage:
  // Push/Pop work the tail, Queue/Dequeue enqueue at the tail and dequeue from the head.
  // That is why 0x38 and 0x40 have identical bodies -- they are distinct MacApp entry
  // points, not one method duplicated.
  virtual POSITION Push(void* item = 0);
  virtual void* Pop(); // MacApp TList::Pop -- removes the tail
  virtual POSITION Queue(void* item = 0);
  virtual void* Dequeue(); // MacApp TList::Dequeue -- removes the head
  virtual int GetCount();
  virtual void* GetEntryByOrdinal(int ordinal = 0);
  virtual void RemoveAtOrdinal(int ordinal);
  virtual void FreePayloads();
  virtual void FreePayloadsAndDestroy();
  virtual void RemoveAll();
  virtual void SetAtOrdinal(int ordinal, void** entryPtr, int unusedFlag);
  // --- MacApp TSortedList sort family (names from the Mac oracle; slot bodies read
  // from the raw listings -- ordinals are 1-based) ---
  // Sort() = QuickSort(1, GetCount(), &DispatchTSortedListDefaultCompare, this).
  virtual void Sort(); // slot 0x64 0x487d90
  // SortBy: same as Sort with a caller-supplied comparator+context (evidence: the
  // auto-deploy strategies at 0x59bcf0/0x59bf20 push (&comparator, 0)).
  virtual void SortBy(TSortedListCompareFunc compare, void* context); // slot 0x68 0x487dd0
  // Default comparator: unsigned three-way compare of the raw payload values (Mac:
  // Compare(TObject*, TObject*) returning a short CompareResult).
  virtual short Compare(void* a, void* b); // slot 0x6c 0x487b30
  virtual void QuickSort(int lo, int hi, TSortedListCompareFunc compare,
                         void* context); // slot 0x70 0x487b60
  // Hoare partition core over ordinals [lo, hi]; pivot = payload at ordinal lo.
  virtual int QSPartitionCore(int lo, int hi, TSortedListCompareFunc compare,
                              void* context); // slot 0x74 0x487bd0
  // Mac QSPartition: swaps a random ordinal into the pivot position, then runs the core.
  virtual int QSPartition(int lo, int hi, TSortedListCompareFunc compare,
                          void* context); // slot 0x78 0x487cc0

  CPtrList listState; // +0x04

  // Defined inline (like the original): construction sites inline the TObject-vtbl +
  // CPtrList(10) sequence (e.g. 0x4a18f0); the binary also carries a COMDAT copy at
  // 0x4a8640 that two call sites invoke non-inlined.
  TSortedList() : listState(10) {}
};

ASSERT_SIZE(TSortedList, 0x20);
