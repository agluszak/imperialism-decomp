#include "game/TSortedList.h"

#include <stdlib.h>
#include "game/TMission.h"

// Default-compare trampoline whose address Sort() passes as the comparator: adapts the
// three-arg __cdecl comparator shape onto the virtual Compare of the list supplied as
// context. (Ghidra: OrphanCallChain_C1_I08_00487a60.)
// FUNCTION: IMPERIALISM 0x00487a60
static short __cdecl DispatchTSortedListDefaultCompare(void* a, void* b, void* context) {
  return static_cast<TSortedList*>(context)->Compare(a, b);
}

// SYNTHETIC: IMPERIALISM 0x00487a90
// TSortedList::CreateObject

// SYNTHETIC: IMPERIALISM 0x00487b10
// TSortedList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSortedList, TObject)

// FUNCTION: IMPERIALISM 0x00487b30
short TSortedList::Compare(void* a, void* b) {
  if (reinterpret_cast<unsigned int>(a) > reinterpret_cast<unsigned int>(b)) {
    return 1;
  }
  if (reinterpret_cast<unsigned int>(a) < reinterpret_cast<unsigned int>(b)) {
    return -1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487b60
void TSortedList::QuickSort(int lo, int hi, TSortedListCompareFunc compare, void* context) {
  if (lo < hi) {
    int pivot = QSPartition(lo, hi, compare, context);
    QuickSort(lo, pivot, compare, context);
    QuickSort(pivot + 1, hi, compare, context);
  }
}

// FUNCTION: IMPERIALISM 0x00487bd0
int TSortedList::QSPartitionCore(int lo, int hi, TSortedListCompareFunc compare, void* context) {
  if (lo >= hi) {
    return hi;
  }
  void* pivot = GetEntryByOrdinal(lo);
  int below = lo - 1;
  int above = hi + 1;
  for (;;) {
    do {
      above--;
    } while (compare(pivot, GetEntryByOrdinal(above), context) <= -1);
    do {
      below++;
    } while (compare(pivot, GetEntryByOrdinal(below), context) >= 1);
    if (above <= below) {
      return above;
    }
    void* belowEntry = GetEntryByOrdinal(below);
    void* aboveEntry = GetEntryByOrdinal(above);
    SetAtOrdinal(below, &aboveEntry, 1);
    SetAtOrdinal(above, &belowEntry, 1);
  }
}

// FUNCTION: IMPERIALISM 0x00487cc0
int TSortedList::QSPartition(int lo, int hi, TSortedListCompareFunc compare, void* context) {
  int pivotOrdinal = lo;
  if (lo != hi) {
    pivotOrdinal = static_cast<int>(rand()) % abs(hi - lo) + lo;
  }
  // Swap the random pick into the pivot position through the public CPtrList API
  // (FindIndex+SetAt compile to the same node-data stores the original emits).
  void* loEntry = GetEntryByOrdinal(lo);
  void* pivotEntry = GetEntryByOrdinal(pivotOrdinal);
  listState.SetAt(listState.FindIndex(lo - 1), pivotEntry);
  listState.SetAt(listState.FindIndex(pivotOrdinal - 1), loEntry);
  return QSPartitionCore(lo, hi, compare, context);
}

// FUNCTION: IMPERIALISM 0x00487d90
void TSortedList::Sort() {
  if (GetCount() > 0) {
    QuickSort(1, GetCount(), &DispatchTSortedListDefaultCompare, this);
  }
}

// FUNCTION: IMPERIALISM 0x00487dd0
void TSortedList::SortBy(TSortedListCompareFunc compare, void* context) {
  if (GetCount() > 0) {
    QuickSort(1, GetCount(), compare, context);
  }
}

// FUNCTION: IMPERIALISM 0x00487e10
int TSortedList::FindOneBasedOrdinalOf(void* item) {
  POSITION position = listState.GetHeadPosition();
  int ordinal = 1;
  while (position != nullptr) {
    if (listState.GetNext(position) == item) {
      return ordinal;
    }
    ++ordinal;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004885d0
POSITION TSortedList::AddHead(void* item) {
  return this->listState.AddHead(item);
}

// FUNCTION: IMPERIALISM 0x004885f0
POSITION TSortedList::AddHeadEx(void* item, int unused1, int unused2) {
  (void)unused1;
  (void)unused2;
  return this->listState.AddHead(item);
}

// FUNCTION: IMPERIALISM 0x00488610
POSITION TSortedList::AddTail(void* item) {
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x00488630
POSITION TSortedList::AddTailEx(void* item, int unused1, int unused2) {
  (void)unused1;
  (void)unused2;
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x00488650
POSITION TSortedList::AddTailSlot38(void* item) {
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x00488670
void* TSortedList::RemoveTail() {
  return this->listState.RemoveTail();
}

// FUNCTION: IMPERIALISM 0x00488690
POSITION TSortedList::AddTailSlot40(void* item) {
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x004886b0
void* TSortedList::RemoveHead() {
  return this->listState.RemoveHead();
}

// Repo convenience only (no address claim): callers store ordinals/ints in the
// payload slots, so this narrows GetEntryByOrdinal's pointer to int.
int TSortedList::GetIntByOrdinal(int ordinal) {
  void* entry = GetEntryByOrdinal(ordinal);
  return reinterpret_cast<int>(entry);
}

// FUNCTION: IMPERIALISM 0x004886d0
int TSortedList::GetCount() {
  return this->listState.GetCount();
}

// FUNCTION: IMPERIALISM 0x004886f0
void* TSortedList::GetEntryByOrdinal(int ordinal) {
  POSITION pos = this->listState.FindIndex(ordinal - 1);
  return pos != NULL ? this->listState.GetAt(pos) : 0;
}

// FUNCTION: IMPERIALISM 0x00488720
void TSortedList::RemoveAtOrdinal(int oneBasedIndex) {
  POSITION pos = this->listState.FindIndex(oneBasedIndex - 1);
  if (pos != 0) {
    this->listState.RemoveAt(pos);
  }
}

// FUNCTION: IMPERIALISM 0x00488750
void TSortedList::FreePayloads() {
  if (this->listState.IsEmpty()) {
    return;
  }
  do {
    void* payload = this->listState.RemoveHead();
    if (payload != 0) {
      static_cast<TMission*>(payload)->Free();
    }
  } while (!this->listState.IsEmpty());
}

// FUNCTION: IMPERIALISM 0x00488790
void TSortedList::Free() {
  delete this;
}

// FUNCTION: IMPERIALISM 0x004887b0
void TSortedList::FreePayloadsAndDestroy() {
  this->FreePayloads();
  this->Free();
}

// FUNCTION: IMPERIALISM 0x004887e0
void TSortedList::RemoveAll() {
  this->listState.RemoveAll();
}

// FUNCTION: IMPERIALISM 0x00488800
void TSortedList::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00488820
void TSortedList::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00488840
void TSortedList::SetAtOrdinal(int ordinal, void** entryPtr, int unusedFlag) {
  (void)unusedFlag;
  POSITION pos = this->listState.FindIndex(ordinal - 1);
  if (pos != NULL) {
    this->listState.SetAt(pos, *entryPtr);
  }
}

// SYNTHETIC: IMPERIALISM 0x004888f0
// TSortedList::`scalar deleting destructor'
