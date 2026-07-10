#include "game/TPtrList.h"

// SYNTHETIC: IMPERIALISM 0x00488510
// TPtrList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPtrList, TSortedPtrList)

TPtrList::TPtrList() {}

void* TPtrList::GetTPtrListClassNamePointer() {
  return RUNTIME_CLASS(TPtrList);
}

int TPtrList::VirtualSlot6C() {
  return 0;
}

int TPtrList::VirtualSlot70() {
  return 0;
}

int TPtrList::VirtualSlot74() {
  return 0;
}

int TPtrList::VirtualSlot78() {
  return 0;
}

int TPtrList::VirtualSlot64() {
  return 0;
}

int TPtrList::SortEntriesWithComparator(int(__cdecl* compare)(void*, void*), int unused) {
  (void)compare;
  (void)unused;
  return 0;
}

POSITION TPtrList::AddHeadSlot28(void* item) {
  (void)item;
  return NULL;
}

POSITION TPtrList::AddHeadSlot2C(void* item, int unused1, int unused2) {
  (void)item;
  (void)unused1;
  (void)unused2;
  return NULL;
}

POSITION TPtrList::AddTailSlot30(void* item) {
  (void)item;
  return NULL;
}

POSITION TPtrList::AddTailSlot34(void* item, int unused1, int unused2) {
  (void)item;
  (void)unused1;
  (void)unused2;
  return NULL;
}

POSITION TPtrList::AddTailSlot38(void* item) {
  (void)item;
  return NULL;
}

void* TPtrList::RemoveTailSlot3C() {
  return 0;
}

POSITION TPtrList::AddTailSlot40(void* item) {
  (void)item;
  return NULL;
}

void* TPtrList::RemoveHeadSlot44() {
  return 0;
}

int TPtrList::GetIntByOrdinalSlot24(int ordinal) {
  void* entry = GetEntryByOrdinalSlot4C(ordinal);
  return reinterpret_cast<int>(entry);
}

int TPtrList::GetCountSlot48() {
  return 0;
}

void* TPtrList::GetEntryByOrdinalSlot4C(int ordinal) {
  (void)ordinal;
  return 0;
}

void TPtrList::RemoveAtOrdinalSlot50(int oneBasedIndex) {
  (void)oneBasedIndex;
}

void TPtrList::FreePayloadsSlot54() {}

void TPtrList::FreePayloadsAndDestroySlot58() {}

void TPtrList::RemoveAllSlot5C() {}

void TPtrList::SetAtOrdinalSlot60(int ordinal, void** entryPtr, int unusedFlag) {
  (void)ordinal;
  (void)entryPtr;
  (void)unusedFlag;
}

// SYNTHETIC: IMPERIALISM 0x004884c0
// TPtrList::`scalar deleting destructor'
