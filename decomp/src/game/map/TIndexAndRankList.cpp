#include "game/map/TIndexAndRankList.h"

#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TIndexAndRankList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x00534870
TIndexAndRankList::TIndexAndRankList() {}

// FUNCTION: IMPERIALISM 0x005348f0
void TIndexAndRankList::IIndexAndRankList() {
  recordSize = 6;
}

// FUNCTION: IMPERIALISM 0x00534910
short TIndexAndRankList::Compare(void* a, void* b) {
  short aKey = static_cast<IndexAndRankRecord*>(a)->value;
  short bKey = static_cast<IndexAndRankRecord*>(b)->value;
  if (aKey < bKey) {
    return 1;
  }
  return ((aKey <= bKey) - 1 & 0xfffffffe) + 1;
}
