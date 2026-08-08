#include "game/military/TArmyStackList.h"
#include "game/military/TArmyStack.h"
// SYNTHETIC: IMPERIALISM 0x004a83b0
// TArmyStackList::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a8430
// TArmyStackList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyStackList, TSortedList)

// SYNTHETIC: IMPERIALISM 0x004a84c0
// TArmyStackList::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004a84f0
TArmyStackList::~TArmyStackList() {}

// FUNCTION: IMPERIALISM 0x004a8560
short TArmyStackList::Compare(void* a, void* b) {
  short aKey = static_cast<TArmyStack*>(a)->field6;
  short bKey = static_cast<TArmyStack*>(b)->field6;
  if (aKey < bKey) {
    return 1;
  }
  if (aKey > bKey) {
    return -1;
  }
  return 0;
}
