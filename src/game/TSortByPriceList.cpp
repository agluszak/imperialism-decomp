#include "game/TSortByPriceList.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TSortByPriceList, TSortedPtrList)

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x00534680
TSortByPriceList* TSortByPriceList::AllocateAndConstructTSortByPriceList() {
  return new TSortByPriceList();
}

// FUNCTION: IMPERIALISM 0x00534710
TSortByPriceList::TSortByPriceList() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00534740
// TSortByPriceList::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x00534770
// TSortByPriceList::~TSortByPriceList

// FUNCTION: IMPERIALISM 0x005347b0
extern "C" int __stdcall CompareSortByPriceListEntriesByField2Ascending(void* a, void* b) {
  short valA = *reinterpret_cast<short*>(reinterpret_cast<char*>(a) + 2);
  short valB = *reinterpret_cast<short*>(reinterpret_cast<char*>(b) + 2);
  if (valA > valB) {
    return 1;
  }
  return -1;
}
