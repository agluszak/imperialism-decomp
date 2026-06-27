#include "game/TList.h"

IMPLEMENT_DYNCREATE(TList, TSortedList)

TList::TList() {}

// FUNCTION: IMPERIALISM 0x00487e50
TList* TList::CreateTListInstance() {
  return new TList();
}
