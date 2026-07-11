#include "decomp_types.h"
#include "game/TDealList.h"

#include "game/mfc.h"
#include "game/TSortedPtrList.h"

// SYNTHETIC: IMPERIALISM 0x005ba130
// TDealList::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ba1a0
// TDealList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDealList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x005ba1c0
TDealList::TDealList() : TSortedPtrList() {}

// SYNTHETIC: IMPERIALISM 0x005ba1f0
// TDealList::`scalar deleting destructor'
TDealList::~TDealList() {}

// FUNCTION: IMPERIALISM 0x005ba260
int TDealList::CompareUnsignedIntsAscending(int lhs, int rhs) {
  (void)lhs;
  (void)rhs;
  return 0;
}
