#include "game/TSortedPtrList.h"
#include "game/mfc.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
CRuntimeClass g_pClassDescTSortedPtrList = {nullptr, 0, 0, nullptr, nullptr};
}

TSortedPtrList::TSortedPtrList() : TIndexAndRankList() {}

// FUNCTION: IMPERIALISM 0x00488400
TSortedPtrList* TSortedPtrList::ConstructTSortedPtrListBaseState() {
  return new TSortedPtrList();
}

// SYNTHETIC: IMPERIALISM 0x004884c0
// TSortedPtrList::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00488510
CRuntimeClass* TSortedPtrList::GetRuntimeClass() const {
  return &g_pClassDescTSortedPtrList;
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
