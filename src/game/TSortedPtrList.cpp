#include "game/TSortedPtrList.h"
#include "game/mfc.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
CRuntimeClass g_pClassDescTSortedPtrList = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM TODO
TSortedPtrList::TSortedPtrList() : TIndexAndRankList() {}

// FUNCTION: IMPERIALISM TODO
TSortedPtrList::~TSortedPtrList() {}

// FUNCTION: IMPERIALISM 0x00488110
void TSortedPtrList::ResetPtrListAndShrinkCapacity() {
  this->ResetPtrListRecordsSlot1C();
  this->ShrinkCapacitySlot28();
}

// FUNCTION: IMPERIALISM 0x00488160
void* __fastcall GetPtrListEntryByOneBasedIndex(TSortedPtrList* self, int, int oneBasedIndex) {
  if (oneBasedIndex <= self->GetSize()) {
    return self->GetAt(oneBasedIndex - 1);
  }
  return 0;
}

void* TSortedPtrList::GetPtrListEntryByOneBasedIndex(int oneBasedIndex) {
  return ::GetPtrListEntryByOneBasedIndex(this, 0, oneBasedIndex);
}

// FUNCTION: IMPERIALISM 0x004883e0
CRuntimeClass* TSortedPtrList::GetRuntimeClass() const {
  return &g_pClassDescTSortedPtrList;
}

// FUNCTION: IMPERIALISM 0x00488400
TSortedPtrList* TSortedPtrList::ConstructTSortedPtrListBaseState() {
  return new TSortedPtrList();
}
