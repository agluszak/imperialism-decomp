#include "game/TIndexAndRankList.h"

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

TIndexAndRankList::TIndexAndRankList() : CPtrArray() {}

// The ordinary destructor and the scalar deleting destructor below are both
// compiler-generated (implicit) from real inheritance — never hand-written.
// SYNTHETIC: IMPERIALISM 0x00601bc1
// TIndexAndRankList::`scalar deleting destructor'

CRuntimeClass* TIndexAndRankList::GetRuntimeClass() const {
  return 0;
}

// List-operation virtuals (slots 5-16). Vtable-shape placeholders — the real
// implementations are at FUN_00488110/00488160/004881f0; these exist so callers
// dispatch through the native vtable rather than reinterpret_cast to a provisional
// interface.
void TIndexAndRankList::slot14(void*) {}
void TIndexAndRankList::slot18() {}
void TIndexAndRankList::ResetPtrListRecordsSlot1C() {}
void TIndexAndRankList::slot20() {}
void TIndexAndRankList::ReleaseSlot24() {}
void TIndexAndRankList::ShrinkCapacitySlot28() {}
void* TIndexAndRankList::GetEntrySlot2C(int oneBasedIndex) {
  return 0;
}
void TIndexAndRankList::RemoveFirstPairSlot30(int mode) {}
void* TIndexAndRankList::PeekFirstPairSlot34() {
  return 0;
}
void TIndexAndRankList::AddEntrySlot38(void* entry) {}
void TIndexAndRankList::slot3c() {}
void TIndexAndRankList::PushPairSlot40(void* pair) {}
