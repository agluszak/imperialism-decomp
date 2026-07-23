#include "game/TIndexAndRankList.h"

#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x005347e0
// TIndexAndRankList::CreateObject

// SYNTHETIC: IMPERIALISM 0x00534850
// TIndexAndRankList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIndexAndRankList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x00534870
TIndexAndRankList::TIndexAndRankList() {}

// SYNTHETIC: IMPERIALISM 0x005348a0
// TIndexAndRankList::`scalar deleting destructor'
// The list-operation virtuals (slots 0x14-0x40) are inherited unchanged from
// TSortedPtrList; TIndexAndRankList does not override them.

// FUNCTION: IMPERIALISM 0x00534910
short TIndexAndRankList::Compare(void* a, void* b) {
  short aKey = *reinterpret_cast<short*>(static_cast<char*>(a) + 2);
  short bKey = *reinterpret_cast<short*>(static_cast<char*>(b) + 2);
  if (aKey < bKey) {
    return 1;
  }
  return static_cast<short>(((aKey <= bKey) - 1 & 0xfffffffe) + 1);
}
