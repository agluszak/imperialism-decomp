#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/mfc.h"

#include <stdlib.h>

IMPLEMENT_DYNCREATE(TSortedByRelationshipList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x004ee540
TSortedByRelationshipList::TSortedByRelationshipList() : TSortedPtrList() {}

// FUNCTION: IMPERIALISM 0x004ee5c0
void TSortedByRelationshipList::ISortedByRelationshipList() {
  recordSize = 4;
}

// FUNCTION: IMPERIALISM 0x004ee5e0
short TSortedByRelationshipList::Compare(void* a, void* b) {
  short aKey = static_cast<short*>(a)[1];
  short bKey = static_cast<short*>(b)[1];
  if (bKey < aKey) {
    return 1;
  }
  if (aKey < bKey) {
    return -1;
  }
  return rand() % 2 != 0 ? 1 : -1;
}
