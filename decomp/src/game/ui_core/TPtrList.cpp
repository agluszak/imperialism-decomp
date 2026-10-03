#include "game/ui_core/TPtrList.h"

#include <string.h>

IMPLEMENT_DYNCREATE(TPtrList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x00488470
void TPtrList::PrependCopiedRecordToPtrList(void* record) {
  unsigned char* copy = new unsigned char[recordSize14];
  memcpy(copy, record, recordSize14);
  InsertAt(0, copy, 1);
}
