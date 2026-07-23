#include "game/TSortByPriceList.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x005346f0
// TSortByPriceList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSortByPriceList, TSortedPtrList)

// SYNTHETIC: IMPERIALISM 0x00534680
// TSortByPriceList::CreateObject

// FUNCTION: IMPERIALISM 0x00534710
TSortByPriceList::TSortByPriceList() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00534740
// TSortByPriceList::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x00534770
// TSortByPriceList::~TSortByPriceList

// FUNCTION: IMPERIALISM 0x005347b0
short TSortByPriceList::Compare(void* a, void* b) {
  short aKey = *reinterpret_cast<short*>(static_cast<char*>(a) + 2);
  short bKey = *reinterpret_cast<short*>(static_cast<char*>(b) + 2);
  return static_cast<short>(((aKey <= bKey) - 1 & 2) - 1);
}
