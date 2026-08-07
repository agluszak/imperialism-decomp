#include "game/ui_core/TPtrList.h"

#include <string.h>

// SYNTHETIC: IMPERIALISM 0x00488510
// TPtrList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPtrList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x00488470
void TPtrList::PrependCopiedRecordToPtrList(void* record) {
  unsigned char* copy = new unsigned char[recordSize14];
  memcpy(copy, record, recordSize14);
  InsertAt(0, copy, 1);
}

// SYNTHETIC: IMPERIALISM 0x004884c0
// TPtrList::`scalar deleting destructor'
