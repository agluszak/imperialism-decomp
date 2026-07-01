#include "game/TSortedPtrList.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x00488030
// TSortedPtrList::CreateObject

// SYNTHETIC: IMPERIALISM 0x004883e0
// TSortedPtrList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSortedPtrList, CPtrArray)

// FUNCTION: IMPERIALISM 0x004880a0
void TSortedPtrList::ResetPtrListRecordsSlot1C() {}

// FUNCTION: IMPERIALISM 0x004880f0
void TSortedPtrList::slot20() {}

// FUNCTION: IMPERIALISM 0x00488110
void TSortedPtrList::ReleaseSlot24() {
  this->ResetPtrListRecordsSlot1C();
  this->ShrinkCapacitySlot28();
}

// FUNCTION: IMPERIALISM 0x00488140
void TSortedPtrList::ShrinkCapacitySlot28() {}

// FUNCTION: IMPERIALISM 0x00488160
void* TSortedPtrList::GetEntrySlot2C(int oneBasedIndex) {
  if (oneBasedIndex <= this->GetSize()) {
    return this->GetAt(oneBasedIndex - 1);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00488190
void TSortedPtrList::RemoveFirstPairSlot30(int mode) {
  (void)mode;
}

// FUNCTION: IMPERIALISM 0x004881d0
void* TSortedPtrList::PeekFirstPairSlot34() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004881f0
void TSortedPtrList::AddEntrySlot38(void* entry) {
  (void)entry;
}

// FUNCTION: IMPERIALISM 0x004882c0
void TSortedPtrList::slot3c() {}

// FUNCTION: IMPERIALISM 0x00488310
void TSortedPtrList::PushPairSlot40(void* pair) {
  (void)pair;
}

// SYNTHETIC: IMPERIALISM 0x00488390
// TSortedPtrList::`scalar deleting destructor'
TSortedPtrList::~TSortedPtrList() {}

TSortedPtrList::TSortedPtrList() {}

// FUNCTION: IMPERIALISM 0x00488400
TSortedPtrList* TSortedPtrList::ConstructTSortedPtrListBaseState() {
  return new TSortedPtrList();
}

// FUNCTION: IMPERIALISM 0x005e1e50
void TSortedPtrList::slot18() {}

// List-operation virtuals (vtable 0x00649068 slots 0x14-0x40). These are
// TSortedPtrList's own slot implementations; TIndexAndRankList and the other
// derived list classes inherit them unchanged.

// FUNCTION: IMPERIALISM 0x005e1f10
void TSortedPtrList::slot14(void*) {}
