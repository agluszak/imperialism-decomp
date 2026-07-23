#include "game/military/TArmyStackList.h"
// SYNTHETIC: IMPERIALISM 0x004a83b0
// TArmyStackList::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a8430
// TArmyStackList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyStackList, TSortedList)

// FUNCTION: IMPERIALISM 0x004a8450
TArmyStackList::TArmyStackList() : TSortedList() {}

// SYNTHETIC: IMPERIALISM 0x004a84c0
// TArmyStackList::`scalar deleting destructor'
TArmyStackList::~TArmyStackList() {}

// FUNCTION: IMPERIALISM 0x004a8560
short TArmyStackList::Compare(void* a, void* b) {
  short aKey = *reinterpret_cast<short*>(static_cast<char*>(a) + 6);
  short bKey = *reinterpret_cast<short*>(static_cast<char*>(b) + 6);
  if (aKey < bKey) {
    return 1;
  }
  if (aKey > bKey) {
    return -1;
  }
  return 0;
}
