#include "game/ui_core/TPtrList.h"

#include <string.h>

// SYNTHETIC: IMPERIALISM 0x00488510
// TPtrList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPtrList, TSortedPtrList)

// NOOP: verified empty in original 0x00488433 (no standalone TPtrList::TPtrList body exists: CreateObject 0x00488400 inlines this default ctor, calling the CPtrArray base ctor directly at that site)
TPtrList::TPtrList() {}

void* TPtrList::GetTPtrListClassNamePointer() {
  return RUNTIME_CLASS(TPtrList);
}

// FUNCTION: IMPERIALISM 0x00488470
void TPtrList::PrependCopiedRecordToPtrList(void* record) {
  unsigned char* copy = new unsigned char[recordSize14];
  memcpy(copy, record, recordSize14);
  InsertAt(0, copy, 1);
}

// SYNTHETIC: IMPERIALISM 0x004884c0
// TPtrList::`scalar deleting destructor'
