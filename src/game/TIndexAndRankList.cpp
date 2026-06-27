#include "game/TIndexAndRankList.h"

#include "game/mfc.h"

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

IMPLEMENT_DYNCREATE(TIndexAndRankList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x004880a0
void TIndexAndRankList::ResetPtrListRecordsSlot1C() {}

// FUNCTION: IMPERIALISM 0x004880f0
void TIndexAndRankList::slot20() {}

// FUNCTION: IMPERIALISM 0x00488110
void TIndexAndRankList::ReleaseSlot24() {
  this->ResetPtrListRecordsSlot1C();
  this->ShrinkCapacitySlot28();
}

// FUNCTION: IMPERIALISM 0x00488140
void TIndexAndRankList::ShrinkCapacitySlot28() {}

// FUNCTION: IMPERIALISM 0x00488160
void* TIndexAndRankList::GetEntrySlot2C(int oneBasedIndex) {
  if (oneBasedIndex <= this->GetSize()) {
    return this->GetAt(oneBasedIndex - 1);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00488190
void TIndexAndRankList::RemoveFirstPairSlot30(int mode) {
  (void)mode;
}

// FUNCTION: IMPERIALISM 0x004881d0
void* TIndexAndRankList::PeekFirstPairSlot34() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004881f0
void TIndexAndRankList::AddEntrySlot38(void* entry) {
  (void)entry;
}

// FUNCTION: IMPERIALISM 0x004882c0
void TIndexAndRankList::slot3c() {}

// FUNCTION: IMPERIALISM 0x00488310
void TIndexAndRankList::PushPairSlot40(void* pair) {
  (void)pair;
}

TIndexAndRankList::TIndexAndRankList() {}

// SYNTHETIC: IMPERIALISM 0x005348a0
// TIndexAndRankList::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005e1e50
void TIndexAndRankList::slot18() {}

// FUNCTION: IMPERIALISM 0x005e1f10
void TIndexAndRankList::slot14(void*) {}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
