#include "game/TSortedPtrList.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TSortedPtrList, CPtrArray)

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x00488400
TSortedPtrList* TSortedPtrList::ConstructTSortedPtrListBaseState() {
  return new TSortedPtrList();
}

// SYNTHETIC: IMPERIALISM 0x004884c0
// TSortedPtrList::`scalar deleting destructor'
TSortedPtrList::~TSortedPtrList() {}

TSortedPtrList::TSortedPtrList() {}

void TSortedPtrList::slot14(void* message) {
  (void)message;
}
void TSortedPtrList::slot18() {}
void TSortedPtrList::ResetPtrListRecordsSlot1C() {}
void TSortedPtrList::slot20() {}
void TSortedPtrList::ReleaseSlot24() {}
void TSortedPtrList::ShrinkCapacitySlot28() {}
void* TSortedPtrList::GetEntrySlot2C(int oneBasedIndex) {
  (void)oneBasedIndex;
  return 0;
}
void TSortedPtrList::RemoveFirstPairSlot30(int mode) {
  (void)mode;
}
void* TSortedPtrList::PeekFirstPairSlot34() {
  return 0;
}
void TSortedPtrList::AddEntrySlot38(void* entry) {
  (void)entry;
}
void TSortedPtrList::slot3c() {}
void TSortedPtrList::PushPairSlot40(void* pair) {
  (void)pair;
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
