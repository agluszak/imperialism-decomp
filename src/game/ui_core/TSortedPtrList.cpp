#include "game/ui_core/TSortedPtrList.h"

#include <string.h>

#include "game/core/TStream.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x00488030
// TSortedPtrList::CreateObject

// SYNTHETIC: IMPERIALISM 0x004883e0
// TSortedPtrList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSortedPtrList, CPtrArray)

// FUNCTION: IMPERIALISM 0x004880a0
void TSortedPtrList::ClearAndFreeAllPtrListRecords() {
  int ordinal = 1;
  void* record = GetPtrListEntryByOneBasedIndex(1);
  while (record != 0) {
    delete[] static_cast<unsigned char*>(record);
    ordinal++;
    record = GetPtrListEntryByOneBasedIndex(ordinal);
  }
  SetSize(0, -1);
}

// Virtual forwarder: the reset hook simply dispatches the clear-and-free slot.
// FUNCTION: IMPERIALISM 0x004880f0
void TSortedPtrList::InvokePtrListResetHook() {
  ClearAndFreeAllPtrListRecords();
}

// FUNCTION: IMPERIALISM 0x00488110
void TSortedPtrList::ReleasePtrList() {
  ClearAndFreeAllPtrListRecords();
  SelfDelete();
}

// FUNCTION: IMPERIALISM 0x00488140
void TSortedPtrList::SelfDelete() {
  if (this != 0) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x00488160
void* TSortedPtrList::GetPtrListEntryByOneBasedIndex(int oneBasedIndex) {
  if (oneBasedIndex <= GetSize()) {
    return GetAt(oneBasedIndex - 1);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00488190
void TSortedPtrList::RemovePtrListEntryByOneBasedIndexAndFree(int oneBasedIndex) {
  void* record = GetPtrListEntryByOneBasedIndex(oneBasedIndex);
  RemoveAt(oneBasedIndex - 1, 1);
  delete[] static_cast<unsigned char*>(record);
}

// FUNCTION: IMPERIALISM 0x004881d0
void* TSortedPtrList::PeekFirstPtrListEntry() {
  return GetPtrListEntryByOneBasedIndex(1);
}

// Walks the records in order and inserts a copy of `record` before the first entry
// the comparator does not place strictly after it; appends when the list is empty or
// every entry compares as 1.
// FUNCTION: IMPERIALISM 0x004881f0
void TSortedPtrList::InsertCopiedRecordSortedByComparator(void* record) {
  int ordinal = 1;
  void* entry = GetPtrListEntryByOneBasedIndex(1);
  if (entry != 0) {
    do {
      if (Compare(record, entry) != 1) {
        unsigned char* copy = new unsigned char[recordSize14];
        memcpy(copy, record, recordSize14);
        InsertAt(ordinal - 1, copy, 1);
        return;
      }
      ordinal++;
      entry = GetPtrListEntryByOneBasedIndex(ordinal);
    } while (entry != 0);
  }
  AppendCopiedRecordToPtrList(record);
}

// FUNCTION: IMPERIALISM 0x004882c0
void TSortedPtrList::AppendCopiedRecordToPtrList(void* record) {
  unsigned char* copy = new unsigned char[recordSize14];
  memcpy(copy, record, recordSize14);
  SetAtGrow(m_nSize, copy);
}

// FUNCTION: IMPERIALISM 0x00488310
void TSortedPtrList::InsertCopiedRecordAtFrontOfPtrList(void* record) {
  unsigned char* copy = new unsigned char[recordSize14];
  memcpy(copy, record, recordSize14);
  InsertAt(0, copy, 1);
}

// FUNCTION: IMPERIALISM 0x00488360
short TSortedPtrList::Compare(void* a, void* b) {
  if (reinterpret_cast<unsigned int>(a) > reinterpret_cast<unsigned int>(b)) {
    return 1;
  }
  if (reinterpret_cast<unsigned int>(a) < reinterpret_cast<unsigned int>(b)) {
    return -1;
  }
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x00488390
// TSortedPtrList::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004883c0
TSortedPtrList::~TSortedPtrList() {}

// SYNTHETIC: IMPERIALISM 0x00488400
// TPtrList::CreateObject

// FUNCTION: IMPERIALISM 0x005e1e50
void TSortedPtrList::ReadFrom(TStream* stream) {
  stream->ReadBytes(&recordSize14, 2);
  int count = stream->streamSlot50();
  unsigned char* buffer = new unsigned char[recordSize14];
  for (short i = 1; i <= count; i++) {
    stream->ReadBytes(buffer, recordSize14);
    InsertCopiedRecordSortedByComparator(buffer);
  }
  delete[] buffer;
}

// FUNCTION: IMPERIALISM 0x005e1f10
void TSortedPtrList::WriteTo(TStream* stream) {
  stream->WriteBytesSlot78(&recordSize14, 2);
  stream->streamSlot8c(m_nSize);
  for (short i = 1; i <= m_nSize; i++) {
    stream->WriteBytesSlot78(GetPtrListEntryByOneBasedIndex(i), recordSize14);
  }
}
