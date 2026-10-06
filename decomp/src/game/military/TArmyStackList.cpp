#include "game/military/TArmyStackList.h"
#include "game/military/TArmyStack.h"

IMPLEMENT_DYNCREATE(TArmyStackList, TSortedList)

// FUNCTION: IMPERIALISM 0x004a84f0
TArmyStackList::~TArmyStackList() {}

// FUNCTION: IMPERIALISM 0x004a8560
short TArmyStackList::Compare(void* a, void* b) {
  short aKey = static_cast<TArmyStack*>(a)->sortKey;
  short bKey = static_cast<TArmyStack*>(b)->sortKey;
  if (aKey < bKey) {
    return 1;
  }
  if (aKey > bKey) {
    return -1;
  }
  return 0;
}
