#include "game/map/TSortByPriceList.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TSortByPriceList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x00534710
TSortByPriceList::TSortByPriceList() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// FUNCTION: IMPERIALISM 0x00534790
void TSortByPriceList::ISortByPriceList() {
  recordSize14 = 4;
}

// FUNCTION: IMPERIALISM 0x005347b0
short TSortByPriceList::Compare(void* a, void* b) {
  short aKey = static_cast<short*>(a)[1];
  short bKey = static_cast<short*>(b)[1];
  return static_cast<short>(((aKey <= bKey) - 1 & 2) - 1);
}
