#include "game/ui_core/TPtrList.h"

#include <string.h>

IMPLEMENT_DYNCREATE(TPtrList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x00488470
void TPtrList::PrependCopiedRecordToPtrList(void* record) {
  InsertCopiedRecordAtFrontOfPtrList(record);
}
